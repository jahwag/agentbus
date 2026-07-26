// Package bus owns AgentBus delivery semantics. Transport adapters resolve a
// principal and delegate here; they do not implement acknowledgement,
// recipient, or retention rules.
package bus

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sqliteDriver "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrDeliveryConflict       = errors.New("agentbus: unknown, foreign, or superseded delivery id")
	ErrUnknownRecipient       = errors.New("agentbus: unknown recipient (set allow_new to reserve it)")
	ErrInvalidName            = errors.New("agentbus: names must match [a-z0-9][a-z0-9._-]{0,63}")
	ErrMessageTooLarge        = errors.New("agentbus: message exceeds 64 KiB")
	ErrRetiredIdentity        = errors.New("agentbus: mailbox is retired")
	ErrUnknownMessage         = errors.New("agentbus: message is not pending for this mailbox")
	ErrBadToken               = errors.New("agentbus: invalid token")
	ErrInvalidClientMessageID = errors.New("agentbus: client_message_id is required and must not exceed 200 bytes")
	ErrIdempotencyConflict    = errors.New("agentbus: client_message_id reused with different send input")
	ErrInvalidData            = errors.New("agentbus: data must be valid JSON with depth at most 32")
	ErrInvalidReplyTo         = errors.New("agentbus: reply_to must be a msg_ identifier followed by 32 lowercase hex characters")
	ErrSelfSend               = errors.New("agentbus: direct self-send is not allowed")
	ErrLegacySchema           = errors.New("agentbus: pre-receipt database detected; move it aside or migrate it explicitly before startup")
	ErrDatabaseInUse          = errors.New("agentbus: database is already owned by another daemon")
	ErrWaiterLimit            = errors.New("agentbus: too many concurrent waiters")
	ErrBacklogLimit           = errors.New("agentbus: durable backlog limit reached")
	ErrInvalidPagination      = errors.New("agentbus: pagination is out of range")
	ErrInvalidReason          = errors.New("agentbus: audit reason is required and must not exceed 1024 bytes")
	ErrMessageNotFound        = errors.New("agentbus: retained message not found")
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var messageIDRE = regexp.MustCompile(`^msg_[0-9a-f]{32}$`)
var memoryDSNSequence atomic.Uint64

const (
	maxMessageBytes                   = 64 * 1024
	maxBatchBytes                     = 256 * 1024
	batchLimit                        = 100
	maxJSONDepth                      = 32
	maxReservedMailboxes              = 64
	maxMailboxUnsettledReceipts int64 = 10_000
	maxMailboxUnsettledBytes    int64 = 64 * 1024 * 1024
	maxGlobalUnsettledReceipts  int64 = 50_000
	maxGlobalUnsettledBytes     int64 = 256 * 1024 * 1024
	maxDatabaseBytes            int64 = 1 * 1024 * 1024 * 1024
	maxWaitersPerMailbox              = 1
	maxWaiters                        = 32
	maxAuditPageSize                  = 1000
	maxAuditReasonBytes               = 1024
	maxActivityMailboxes              = 256
	maxRecentRoutes                   = 100
)

const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations(
	version INTEGER PRIMARY KEY,
	checksum TEXT NOT NULL,
	applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS mailboxes(
	name TEXT PRIMARY KEY,
	state TEXT NOT NULL CHECK(state IN ('reserved','active','retired')),
	last_seen TEXT,
	retired_at TEXT,
	token_hash TEXT UNIQUE,
	CHECK((state = 'retired' AND retired_at IS NOT NULL AND token_hash IS NULL)
	   OR (state != 'retired' AND retired_at IS NULL))
);
CREATE TABLE IF NOT EXISTS messages(
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	message_id TEXT NOT NULL UNIQUE,
	from_name TEXT NOT NULL,
	to_name TEXT NOT NULL,
	ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
	body TEXT NOT NULL,
	data TEXT,
	reply_to TEXT,
	encoded_bytes INTEGER NOT NULL CHECK(encoded_bytes >= 0),
	client_message_id TEXT NOT NULL,
	UNIQUE(from_name, client_message_id)
);
CREATE INDEX IF NOT EXISTS messages_to_seq ON messages(to_name, seq);
CREATE TABLE IF NOT EXISTS send_dedup(
	from_name TEXT NOT NULL,
	client_message_id TEXT NOT NULL,
	command_hash TEXT NOT NULL,
	message_id TEXT NOT NULL,
	message_seq INTEGER NOT NULL,
	message_ts TEXT NOT NULL,
	to_name TEXT NOT NULL,
	PRIMARY KEY(from_name, client_message_id)
);
CREATE TABLE IF NOT EXISTS batch_deliveries(
	delivery_id TEXT PRIMARY KEY,
	mailbox_name TEXT NOT NULL REFERENCES mailboxes(name),
	state TEXT NOT NULL CHECK(state IN ('outstanding','completed','superseded')),
	through INTEGER NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
	completed_at TEXT,
	superseded_at TEXT
	,UNIQUE(delivery_id, mailbox_name)
	,CHECK(attempts >= 1)
	,CHECK((state = 'outstanding' AND completed_at IS NULL AND superseded_at IS NULL)
	    OR (state = 'completed' AND completed_at IS NOT NULL AND superseded_at IS NULL)
	    OR (state = 'superseded' AND completed_at IS NULL AND superseded_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS one_outstanding_delivery
	ON batch_deliveries(mailbox_name) WHERE state = 'outstanding';
CREATE TABLE IF NOT EXISTS receipts(
	mailbox_name TEXT NOT NULL REFERENCES mailboxes(name),
	message_seq INTEGER NOT NULL REFERENCES messages(seq) ON DELETE CASCADE,
	state TEXT NOT NULL CHECK(state IN ('pending','offered','acked','dead')),
	delivery_id TEXT,
	attempts INTEGER NOT NULL DEFAULT 0,
	first_offered_at TEXT,
	last_offered_at TEXT,
	settled_at TEXT,
	dead_reason TEXT,
	PRIMARY KEY(mailbox_name, message_seq),
	FOREIGN KEY(delivery_id, mailbox_name)
		REFERENCES batch_deliveries(delivery_id, mailbox_name),
	CHECK(attempts >= 0),
	CHECK((state = 'pending' AND delivery_id IS NULL AND settled_at IS NULL AND dead_reason IS NULL)
	   OR (state = 'offered' AND delivery_id IS NOT NULL AND settled_at IS NULL AND dead_reason IS NULL)
	   OR (state = 'acked' AND delivery_id IS NOT NULL AND settled_at IS NOT NULL AND dead_reason IS NULL)
	   OR (state = 'dead' AND delivery_id IS NULL AND settled_at IS NOT NULL AND dead_reason IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS receipts_mailbox_state_seq
	ON receipts(mailbox_name, state, message_seq);
CREATE INDEX IF NOT EXISTS receipts_delivery ON receipts(delivery_id);
CREATE TABLE IF NOT EXISTS audit_events(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	action TEXT NOT NULL,
	mailbox_name TEXT,
	message_id TEXT,
	sender_name TEXT,
	reason TEXT NOT NULL,
	ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);`

type migration struct {
	version int
	sql     string
}

var migrations = []migration{
	{version: 1, sql: schema},
	{version: 2, sql: `
ALTER TABLE mailboxes
	ADD COLUMN credential_generation INTEGER NOT NULL DEFAULT 0
	CHECK(credential_generation >= 0);`},
	{version: 3, sql: `
CREATE TABLE mailbox_activity(
	mailbox_name TEXT PRIMARY KEY REFERENCES mailboxes(name),
	messages_sent INTEGER NOT NULL DEFAULT 0 CHECK(messages_sent >= 0),
	receipts_enqueued INTEGER NOT NULL DEFAULT 0 CHECK(receipts_enqueued >= 0),
	receipts_acked INTEGER NOT NULL DEFAULT 0 CHECK(receipts_acked >= 0),
	receipts_dead INTEGER NOT NULL DEFAULT 0 CHECK(receipts_dead >= 0),
	offer_attempts INTEGER NOT NULL DEFAULT 0 CHECK(offer_attempts >= 0),
	last_sent_at TEXT,
	last_enqueued_at TEXT,
	last_offered_at TEXT,
	last_acked_at TEXT,
	last_dead_at TEXT
);
CREATE TRIGGER activity_message_insert AFTER INSERT ON messages BEGIN
	INSERT INTO mailbox_activity(mailbox_name, messages_sent, last_sent_at)
	VALUES(NEW.from_name, 1, NEW.ts)
	ON CONFLICT(mailbox_name) DO UPDATE SET
		messages_sent = mailbox_activity.messages_sent + 1,
		last_sent_at = excluded.last_sent_at;
END;
CREATE TRIGGER activity_receipt_insert AFTER INSERT ON receipts BEGIN
	INSERT INTO mailbox_activity(mailbox_name, receipts_enqueued, last_enqueued_at)
	VALUES(NEW.mailbox_name, 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	ON CONFLICT(mailbox_name) DO UPDATE SET
		receipts_enqueued = mailbox_activity.receipts_enqueued + 1,
		last_enqueued_at = excluded.last_enqueued_at;
END;
CREATE TRIGGER activity_receipt_update
AFTER UPDATE OF state, attempts ON receipts BEGIN
	INSERT INTO mailbox_activity(
		mailbox_name, receipts_acked, receipts_dead, offer_attempts,
		last_offered_at, last_acked_at, last_dead_at
	) VALUES(
		NEW.mailbox_name,
		CASE WHEN NEW.state = 'acked' AND OLD.state != 'acked' THEN 1 ELSE 0 END,
		CASE WHEN NEW.state = 'dead' AND OLD.state != 'dead' THEN 1 ELSE 0 END,
		CASE WHEN NEW.attempts > OLD.attempts THEN NEW.attempts - OLD.attempts ELSE 0 END,
		CASE WHEN NEW.attempts > OLD.attempts THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') END,
		CASE WHEN NEW.state = 'acked' AND OLD.state != 'acked' THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') END,
		CASE WHEN NEW.state = 'dead' AND OLD.state != 'dead' THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') END
	)
	ON CONFLICT(mailbox_name) DO UPDATE SET
		receipts_acked = mailbox_activity.receipts_acked + excluded.receipts_acked,
		receipts_dead = mailbox_activity.receipts_dead + excluded.receipts_dead,
		offer_attempts = mailbox_activity.offer_attempts + excluded.offer_attempts,
		last_offered_at = COALESCE(excluded.last_offered_at, mailbox_activity.last_offered_at),
		last_acked_at = COALESCE(excluded.last_acked_at, mailbox_activity.last_acked_at),
		last_dead_at = COALESCE(excluded.last_dead_at, mailbox_activity.last_dead_at);
END;`},
	{version: 4, sql: `
CREATE INDEX receipts_message_seq_state ON receipts(message_seq, state);`},
}

type Message struct {
	Seq       int64           `json:"seq"`
	MessageID string          `json:"message_id"`
	From      string          `json:"from"`
	To        string          `json:"to"`
	TS        string          `json:"ts"`
	Body      string          `json:"body"`
	Data      json.RawMessage `json:"data,omitempty"`
	ReplyTo   *string         `json:"reply_to,omitempty"`
}

type Delivery struct {
	ID         string    `json:"delivery_id"`
	Through    int64     `json:"-"` // private storage watermark
	Redelivery bool      `json:"redelivery"`
	Messages   []Message `json:"messages"`
}

type SendOpts struct {
	Body            string
	Data            json.RawMessage
	ReplyTo         *string
	ClientMessageID string
	AllowNew        bool
}

// AuthenticatedPrincipal is a non-secret proof of the credential state that
// authenticated a request. Transport adapters may retain it while a request is
// parked and validate it immediately before exposing a delivery.
type AuthenticatedPrincipal struct {
	Name       string
	Generation int64
}

type PruneResult struct {
	Messages   int64 `json:"messages"`
	Receipts   int64 `json:"receipts"`
	Deliveries int64 `json:"deliveries"`
}

// ActivityCounters records transitions observed after tracking began.
type ActivityCounters struct {
	MessagesSent     int64 `json:"messages_sent"`
	ReceiptsEnqueued int64 `json:"receipts_enqueued"`
	ReceiptsAcked    int64 `json:"receipts_acked"`
	ReceiptsDead     int64 `json:"receipts_dead"`
	OfferAttempts    int64 `json:"offer_attempts"`
}

type ActivityGauges struct {
	PendingReceipts       int64 `json:"pending_receipts"`
	OfferedReceipts       int64 `json:"offered_receipts"`
	OutstandingDeliveries int64 `json:"outstanding_deliveries"`
	MaxAttempts           int64 `json:"max_attempts"`
}

type ActivityMailbox struct {
	Name           string           `json:"name"`
	State          string           `json:"state"`
	LastSeen       string           `json:"last_seen,omitempty"`
	SinceTracking  ActivityCounters `json:"since_tracking"`
	Current        ActivityGauges   `json:"current"`
	LastSentAt     string           `json:"last_sent_at,omitempty"`
	LastEnqueuedAt string           `json:"last_enqueued_at,omitempty"`
	LastOfferedAt  string           `json:"last_offered_at,omitempty"`
	LastAckedAt    string           `json:"last_acked_at,omitempty"`
	LastDeadAt     string           `json:"last_dead_at,omitempty"`
}

type ActivityReport struct {
	AsOf              string            `json:"as_of"`
	TrackingStartedAt string            `json:"tracking_started_at"`
	SinceTracking     ActivityCounters  `json:"since_tracking"`
	Current           ActivityGauges    `json:"current"`
	Mailboxes         []ActivityMailbox `json:"mailboxes"`
	Truncated         bool              `json:"truncated"`
}

// RecentRoute is retained routing metadata. Message content and caller
// idempotency fields are deliberately absent from this inspection surface.
type RecentRoute struct {
	Seq       int64              `json:"seq"`
	MessageID string             `json:"message_id"`
	From      string             `json:"from"`
	To        string             `json:"to"`
	TS        string             `json:"ts"`
	Receipts  ReceiptStateCounts `json:"receipts"`
}

type ReceiptStateCounts struct {
	Pending int64 `json:"pending"`
	Offered int64 `json:"offered"`
	Acked   int64 `json:"acked"`
	Dead    int64 `json:"dead"`
}

type backlogLimits struct {
	mailboxReceipts int64
	mailboxBytes    int64
	globalReceipts  int64
	globalBytes     int64
}

type Bus struct {
	db    *sql.DB
	owner *databaseLock

	mu            sync.Mutex
	waiters       map[string][]chan struct{}
	waiterCount   int
	backlogLimits backlogLimits
}

func Open(path string) (*Bus, error) {
	owner, err := acquireDatabaseLock(path)
	if err != nil {
		return nil, err
	}
	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		owner.release()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := configureDatabaseSizeLimit(db); err != nil {
		db.Close()
		owner.release()
		return nil, mapStorageError(err)
	}
	if err := applyMigrations(db); err != nil {
		db.Close()
		owner.release()
		return nil, mapStorageError(err)
	}
	if path != ":memory:" {
		if err := os.Chmod(path, 0o600); err != nil {
			db.Close()
			owner.release()
			return nil, err
		}
	}
	return &Bus{
		db: db, owner: owner, waiters: make(map[string][]chan struct{}),
		backlogLimits: backlogLimits{
			mailboxReceipts: maxMailboxUnsettledReceipts,
			mailboxBytes:    maxMailboxUnsettledBytes,
			globalReceipts:  maxGlobalUnsettledReceipts,
			globalBytes:     maxGlobalUnsettledBytes,
		},
	}, nil
}

func configureDatabaseSizeLimit(db *sql.DB) error {
	var pageSize int64
	if err := db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return err
	}
	if pageSize <= 0 || pageSize > maxDatabaseBytes {
		return fmt.Errorf("agentbus: invalid SQLite page size %d", pageSize)
	}
	desiredPages := maxDatabaseBytes / pageSize
	var actualPages int64
	if err := db.QueryRow(fmt.Sprintf(`PRAGMA max_page_count = %d`, desiredPages)).Scan(&actualPages); err != nil {
		return err
	}
	if actualPages > desiredPages {
		return fmt.Errorf("%w: existing database exceeds %d-byte hard cap", ErrBacklogLimit, maxDatabaseBytes)
	}
	return nil
}

func applyMigrations(db *sql.DB) error {
	hasHistory, err := tableExists(db, "schema_migrations")
	if err != nil {
		return err
	}
	if !hasHistory {
		legacyMessages, err := tableExists(db, "messages")
		if err != nil {
			return err
		}
		legacyIdentities, err := tableExists(db, "identities")
		if err != nil {
			return err
		}
		if legacyMessages || legacyIdentities {
			return ErrLegacySchema
		}
	}

	applied := make(map[int]string)
	if hasHistory {
		rows, err := db.Query(`SELECT version, checksum FROM schema_migrations ORDER BY version`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var version int
			var checksum string
			if err := rows.Scan(&version, &checksum); err != nil {
				rows.Close()
				return err
			}
			applied[version] = checksum
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	known := make(map[int]string, len(migrations))
	for _, m := range migrations {
		sum := sha256.Sum256([]byte(m.sql))
		known[m.version] = hex.EncodeToString(sum[:])
	}
	// Refuse downgrades and edited migration history before executing any DDL.
	for version, stored := range applied {
		checksum, ok := known[version]
		if !ok {
			return fmt.Errorf("agentbus: database schema version %d is newer than this binary", version)
		}
		if stored != checksum {
			return fmt.Errorf("agentbus: migration %d checksum mismatch", version)
		}
	}
	for _, m := range migrations {
		checksum := known[m.version]
		if _, ok := applied[m.version]; ok {
			continue
		}
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("agentbus: apply migration %d: %w", m.version, err)
		}
		if _, err := tx.Exec(
			`INSERT INTO schema_migrations(version, checksum) VALUES(?,?)`, m.version, checksum); err != nil {
			tx.Rollback()
			return fmt.Errorf("agentbus: record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("agentbus: commit migration %d: %w", m.version, err)
		}
	}
	return nil
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count)
	return count != 0, err
}

func sqliteDSN(path string) string {
	if path == ":memory:" {
		return fmt.Sprintf(
			"file:agentbus-memory-%d?mode=memory&cache=private&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)",
			memoryDSNSequence.Add(1))
	}
	u := &url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("_pragma", "foreign_keys(ON)")
	// modernc accepts repeated _pragma values but url.Values.Set cannot express
	// them, so append the remaining fixed settings explicitly.
	u.RawQuery = q.Encode() + "&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)"
	return u.String()
}

func (b *Bus) Close() error {
	dbErr := b.db.Close()
	lockErr := b.owner.release()
	return errors.Join(dbErr, lockErr)
}

func (b *Bus) Send(from, to string, opts SendOpts) (_ Message, err error) {
	defer func() { err = mapStorageError(err) }()
	if !nameRE.MatchString(from) || (to != "*" && !nameRE.MatchString(to)) {
		return Message{}, ErrInvalidName
	}
	if to == from {
		return Message{}, ErrSelfSend
	}
	if opts.ClientMessageID == "" || len(opts.ClientMessageID) > 200 {
		return Message{}, ErrInvalidClientMessageID
	}
	if opts.ReplyTo != nil && !messageIDRE.MatchString(*opts.ReplyTo) {
		return Message{}, ErrInvalidReplyTo
	}
	data, err := canonicalData(opts.Data)
	if err != nil {
		return Message{}, err
	}
	opts.Data = data
	messageBytes := int64(encodedMessageBytes(from, to, opts))
	if messageBytes > maxMessageBytes {
		return Message{}, ErrMessageTooLarge
	}

	tx, err := b.db.Begin()
	if err != nil {
		return Message{}, err
	}
	defer tx.Rollback()

	if err := activateMailbox(tx, from); err != nil {
		return Message{}, err
	}
	commandHash := hashSend(to, opts)
	var dedupHash, dedupMessageID, dedupTS, dedupTo string
	var dedupSeq int64
	err = tx.QueryRow(
		`SELECT command_hash, message_id, message_seq, message_ts, to_name
		 FROM send_dedup WHERE from_name = ? AND client_message_id = ?`,
		from, opts.ClientMessageID).
		Scan(&dedupHash, &dedupMessageID, &dedupSeq, &dedupTS, &dedupTo)
	if err == nil {
		if dedupHash != commandHash {
			return Message{}, ErrIdempotencyConflict
		}
		m := Message{
			Seq: dedupSeq, MessageID: dedupMessageID, From: from, To: dedupTo,
			TS: dedupTS, Body: opts.Body, Data: opts.Data, ReplyTo: opts.ReplyTo,
		}
		if err := tx.Commit(); err != nil {
			return Message{}, err
		}
		return m, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Message{}, err
	}
	var existingSeq int64
	err = tx.QueryRow(`SELECT seq FROM messages WHERE from_name = ? AND client_message_id = ?`, from, opts.ClientMessageID).Scan(&existingSeq)
	if err == nil {
		m, err := loadMessage(tx, existingSeq)
		if err != nil {
			return Message{}, err
		}
		if !sameSend(m, to, opts) {
			return Message{}, ErrIdempotencyConflict
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO send_dedup(from_name, client_message_id, command_hash,
			 message_id, message_seq, message_ts, to_name) VALUES(?,?,?,?,?,?,?)`,
			from, opts.ClientMessageID, commandHash, m.MessageID, m.Seq, m.TS, m.To); err != nil {
			return Message{}, err
		}
		if err := tx.Commit(); err != nil {
			return Message{}, err
		}
		return m, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Message{}, err
	}

	if to != "*" {
		state, err := mailboxState(tx, to)
		switch {
		case errors.Is(err, sql.ErrNoRows) && opts.AllowNew:
			var reserved int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM mailboxes WHERE state = 'reserved'`).Scan(&reserved); err != nil {
				return Message{}, err
			}
			if reserved >= maxReservedMailboxes {
				return Message{}, ErrBacklogLimit
			}
			if _, err := tx.Exec(`INSERT INTO mailboxes(name, state) VALUES(?, 'reserved')`, to); err != nil {
				return Message{}, err
			}
		case errors.Is(err, sql.ErrNoRows):
			return Message{}, ErrUnknownRecipient
		case err != nil:
			return Message{}, err
		case state == "retired":
			return Message{}, ErrRetiredIdentity
		}
	}
	recipients := []string{to}
	if to == "*" {
		recipients, err = activeBroadcastRecipients(tx, from)
		if err != nil {
			return Message{}, err
		}
	}
	if err := b.requireBacklogCapacity(tx, recipients, messageBytes); err != nil {
		return Message{}, err
	}

	messageID, err := newID("msg")
	if err != nil {
		return Message{}, err
	}
	var storedData any
	if len(opts.Data) > 0 {
		storedData = string(opts.Data)
	}
	var replyTo any
	if opts.ReplyTo != nil {
		replyTo = *opts.ReplyTo
	}
	res, err := tx.Exec(
		`INSERT INTO messages(message_id, from_name, to_name, body, data, reply_to, encoded_bytes, client_message_id)
		 VALUES(?,?,?,?,?,?,?,?)`,
		messageID, from, to, opts.Body, storedData, replyTo, messageBytes, opts.ClientMessageID)
	if err != nil {
		return Message{}, err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return Message{}, err
	}
	for _, recipient := range recipients {
		if _, err := tx.Exec(
			`INSERT INTO receipts(mailbox_name, message_seq, state) VALUES(?,?,'pending')`, recipient, seq); err != nil {
			return Message{}, err
		}
	}
	m, err := loadMessage(tx, seq)
	if err != nil {
		return Message{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO send_dedup(from_name, client_message_id, command_hash,
		 message_id, message_seq, message_ts, to_name) VALUES(?,?,?,?,?,?,?)`,
		from, opts.ClientMessageID, commandHash, m.MessageID, m.Seq, m.TS, m.To); err != nil {
		return Message{}, err
	}
	if err := tx.Commit(); err != nil {
		return Message{}, err
	}
	b.wake(to)
	return m, nil
}
func mapStorageError(err error) error {
	if err == nil {
		return nil
	}
	var sqliteErr *sqliteDriver.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code()&0xff == sqlite3.SQLITE_FULL {
		return fmt.Errorf("%w: SQLite storage limit reached", ErrBacklogLimit)
	}
	return err
}

func activeBroadcastRecipients(tx *sql.Tx, from string) ([]string, error) {
	rows, err := tx.Query(
		`SELECT name FROM mailboxes WHERE state = 'active' AND name != ? ORDER BY name`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recipients []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		recipients = append(recipients, name)
	}
	return recipients, rows.Err()
}

func (b *Bus) requireBacklogCapacity(tx *sql.Tx, recipients []string, messageBytes int64) error {
	for _, recipient := range recipients {
		var receipts, bytes int64
		if err := tx.QueryRow(
			`SELECT COUNT(*), COALESCE(SUM(m.encoded_bytes), 0)
			 FROM receipts r JOIN messages m ON m.seq = r.message_seq
			 WHERE r.mailbox_name = ? AND r.state IN ('pending','offered')`, recipient).
			Scan(&receipts, &bytes); err != nil {
			return err
		}
		if receipts+1 > b.backlogLimits.mailboxReceipts || bytes+messageBytes > b.backlogLimits.mailboxBytes {
			return ErrBacklogLimit
		}
	}
	var receipts, bytes int64
	if err := tx.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(m.encoded_bytes), 0)
		 FROM receipts r JOIN messages m ON m.seq = r.message_seq
		 WHERE r.state IN ('pending','offered')`).Scan(&receipts, &bytes); err != nil {
		return err
	}
	newReceipts := int64(len(recipients))
	if receipts+newReceipts > b.backlogLimits.globalReceipts ||
		bytes+newReceipts*messageBytes > b.backlogLimits.globalBytes {
		return ErrBacklogLimit
	}
	return nil
}

func canonicalData(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if !json.Valid(raw) || jsonDepth(raw) > maxJSONDepth {
		return nil, ErrInvalidData
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrInvalidData
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidData
	}
	return json.RawMessage(canonical), nil
}

func jsonDepth(raw []byte) int {
	depth, maxDepth := 0, 0
	inString, escaped := false, false
	for _, c := range raw {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}', ']':
			depth--
		}
	}
	return maxDepth
}

func encodedMessageBytes(from, to string, opts SendOpts) int {
	// IDs and timestamps have fixed widths. MaxInt64 reserves the largest
	// positive AUTOINCREMENT sequence so every actual encoded Message is no
	// larger than this admission-time calculation.
	v := Message{
		Seq:       9_223_372_036_854_775_807,
		MessageID: "msg_ffffffffffffffffffffffffffffffff",
		From:      from,
		To:        to,
		TS:        "9999-12-31T23:59:59.999Z",
		Body:      opts.Body,
		Data:      opts.Data,
		ReplyTo:   opts.ReplyTo,
	}
	b, _ := json.Marshal(v)
	return len(b)
}

func sameSend(m Message, to string, opts SendOpts) bool {
	if m.To != to || m.Body != opts.Body || string(m.Data) != string(opts.Data) {
		return false
	}
	if m.ReplyTo == nil || opts.ReplyTo == nil {
		return m.ReplyTo == nil && opts.ReplyTo == nil
	}
	return *m.ReplyTo == *opts.ReplyTo
}

func hashSend(to string, opts SendOpts) string {
	command := struct {
		To      string          `json:"to"`
		Body    string          `json:"body"`
		Data    json.RawMessage `json:"data,omitempty"`
		ReplyTo *string         `json:"reply_to,omitempty"`
	}{to, opts.Body, opts.Data, opts.ReplyTo}
	raw, _ := json.Marshal(command)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// WaitDelivery activates the mailbox before registering, then uses
// register-before-check and a predicate loop. Parked waiters hold no database
// connection or transaction.
func (b *Bus) WaitDelivery(ctx context.Context, name string) (*Delivery, error) {
	if err := b.activate(name); err != nil {
		return nil, err
	}
	for {
		ch, err := b.register(name)
		if err != nil {
			return nil, err
		}
		d, err := b.NextDelivery(name)
		if d != nil || err != nil {
			b.unregister(name, ch)
			return d, err
		}
		select {
		case <-ctx.Done():
			b.unregister(name, ch)
			return nil, nil
		case <-ch:
		}
	}
}

func (b *Bus) activate(name string) (err error) {
	defer func() { err = mapStorageError(err) }()
	if !nameRE.MatchString(name) {
		return ErrInvalidName
	}
	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := activateMailbox(tx, name); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *Bus) NextDelivery(name string) (_ *Delivery, err error) {
	defer func() { err = mapStorageError(err) }()
	if !nameRE.MatchString(name) {
		return nil, ErrInvalidName
	}
	tx, err := b.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := activateMailbox(tx, name); err != nil {
		return nil, err
	}

	var d Delivery
	var state string
	err = tx.QueryRow(
		`SELECT delivery_id, through, attempts, state FROM batch_deliveries
		 WHERE mailbox_name = ? AND state = 'outstanding'`, name).
		Scan(&d.ID, &d.Through, new(int), &state)
	switch {
	case err == nil:
		d.Redelivery = true
		if d.Messages, err = loadDeliveryMessages(tx, name, d.ID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(
			`UPDATE batch_deliveries SET attempts = attempts + 1 WHERE delivery_id = ?`, d.ID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(
			`UPDATE receipts SET attempts = attempts + 1,
			 last_offered_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
			 WHERE delivery_id = ? AND state = 'offered'`, d.ID); err != nil {
			return nil, err
		}
		return &d, tx.Commit()
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}

	msgs, err := loadPendingMessages(tx, name)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, tx.Commit()
	}
	d.ID, err = newID("dlv")
	if err != nil {
		return nil, err
	}
	d.Messages = msgs
	d.Through = msgs[len(msgs)-1].Seq
	for _, m := range msgs {
		var attempts int
		if err := tx.QueryRow(
			`SELECT attempts FROM receipts WHERE mailbox_name = ? AND message_seq = ?`,
			name, m.Seq).Scan(&attempts); err != nil {
			return nil, err
		}
		if attempts > 0 {
			d.Redelivery = true
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO batch_deliveries(delivery_id, mailbox_name, state, through)
		 VALUES(?,?,'outstanding',?)`, d.ID, name, d.Through); err != nil {
		return nil, err
	}
	for _, m := range msgs {
		res, err := tx.Exec(
			`UPDATE receipts SET state = 'offered', delivery_id = ?, attempts = attempts + 1,
			 first_offered_at = COALESCE(first_offered_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
			 last_offered_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
			 WHERE mailbox_name = ? AND message_seq = ? AND state = 'pending'`,
			d.ID, name, m.Seq)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, errors.New("agentbus: receipt changed while creating delivery")
		}
	}
	return &d, tx.Commit()
}

func (b *Bus) Ack(name, deliveryID string) (_ int64, err error) {
	defer func() { err = mapStorageError(err) }()
	if !nameRE.MatchString(name) {
		return 0, ErrInvalidName
	}
	tx, err := b.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var state string
	var through int64
	err = tx.QueryRow(
		`SELECT state, through FROM batch_deliveries WHERE delivery_id = ? AND mailbox_name = ?`,
		deliveryID, name).Scan(&state, &through)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrDeliveryConflict
	}
	if err != nil {
		return 0, err
	}
	switch state {
	case "completed":
		return through, tx.Commit()
	case "superseded":
		return 0, ErrDeliveryConflict
	case "outstanding":
		if err := requireActiveMailbox(tx, name); err != nil {
			return 0, err
		}
		res, err := tx.Exec(
			`UPDATE receipts SET state = 'acked', settled_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
			 WHERE mailbox_name = ? AND delivery_id = ? AND state = 'offered'`, name, deliveryID)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return 0, ErrDeliveryConflict
		}
		if _, err := tx.Exec(
			`UPDATE batch_deliveries SET state = 'completed',
			 completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
			 WHERE delivery_id = ? AND state = 'outstanding'`, deliveryID); err != nil {
			return 0, err
		}
		return through, tx.Commit()
	default:
		return 0, ErrDeliveryConflict
	}
}

func (b *Bus) Skip(name, messageID, reason string) (err error) {
	defer func() { err = mapStorageError(err) }()
	if !nameRE.MatchString(name) {
		return ErrInvalidName
	}
	if err := validateAuditReason(reason); err != nil {
		return err
	}
	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var seq int64
	var state string
	var sender string
	var deliveryID sql.NullString
	err = tx.QueryRow(
		`SELECT r.message_seq, r.state, r.delivery_id, m.from_name
		 FROM receipts r JOIN messages m ON m.seq = r.message_seq
		 WHERE r.mailbox_name = ? AND m.message_id = ?`, name, messageID).
		Scan(&seq, &state, &deliveryID, &sender)
	if errors.Is(err, sql.ErrNoRows) || state == "acked" {
		return ErrUnknownMessage
	}
	if err != nil {
		return err
	}
	if state == "dead" {
		return tx.Commit()
	}
	if _, err := tx.Exec(
		`UPDATE receipts SET state = 'dead', delivery_id = NULL,
		 settled_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), dead_reason = ?
		 WHERE mailbox_name = ? AND message_seq = ?`, reason, name, seq); err != nil {
		return err
	}
	if deliveryID.Valid {
		if _, err := tx.Exec(
			`UPDATE batch_deliveries SET state = 'superseded',
			 superseded_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
			 WHERE delivery_id = ? AND state = 'outstanding'`, deliveryID.String); err != nil {
			return err
		}
		if _, err := tx.Exec(
			`UPDATE receipts SET state = 'pending', delivery_id = NULL
			 WHERE delivery_id = ? AND state = 'offered'`, deliveryID.String); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO audit_events(action, mailbox_name, message_id, sender_name, reason)
		 VALUES('skip',?,?,?,?)`, name, messageID, sender, reason); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	b.wake(name)
	return nil
}

func (b *Bus) Retire(name, reason string) (err error) {
	defer func() { err = mapStorageError(err) }()
	if !nameRE.MatchString(name) {
		return ErrInvalidName
	}
	if err := validateAuditReason(reason); err != nil {
		return err
	}
	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, err := mailboxState(tx, name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(
			`INSERT INTO mailboxes(name, state, retired_at) VALUES(?, 'retired', strftime('%Y-%m-%dT%H:%M:%fZ','now'))`, name); err != nil {
			return err
		}
	case err != nil:
		return err
	case state == "retired":
		return tx.Commit()
	}
	if _, err := tx.Exec(
		`UPDATE batch_deliveries SET state = 'superseded',
		 superseded_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
		 WHERE mailbox_name = ? AND state = 'outstanding'`, name); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO audit_events(action, mailbox_name, message_id, sender_name, reason)
		 SELECT 'retire_receipt', ?, m.message_id, m.from_name, ?
		 FROM receipts r JOIN messages m ON m.seq = r.message_seq
		 WHERE r.mailbox_name = ? AND r.state IN ('pending','offered')`,
		name, reason, name); err != nil {
		return err
	}
	_, err = tx.Exec(
		`UPDATE receipts SET state = 'dead', delivery_id = NULL,
		 settled_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), dead_reason = ?
		 WHERE mailbox_name = ? AND state IN ('pending','offered')`, reason, name)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`UPDATE mailboxes SET state = 'retired', token_hash = NULL,
		 retired_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE name = ?`, name); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO audit_events(action, mailbox_name, reason) VALUES('retire',?,?)`, name, reason); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	b.wake(name)
	return nil
}

func (b *Bus) Prune(before time.Time) (_ PruneResult, err error) {
	defer func() { err = mapStorageError(err) }()
	tx, err := b.db.Begin()
	if err != nil {
		return PruneResult{}, err
	}
	defer tx.Rollback()
	cutoff := before.UTC().Format("2006-01-02T15:04:05.000Z")
	var result PruneResult
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM receipts r JOIN messages m ON m.seq = r.message_seq
		 WHERE r.state IN ('acked','dead')
		   AND NOT EXISTS (SELECT 1 FROM receipts open
		                   WHERE open.message_seq = m.seq AND open.state IN ('pending','offered'))
		   AND NOT EXISTS (SELECT 1 FROM receipts recent
		                   WHERE recent.message_seq = m.seq
		                     AND (recent.settled_at IS NULL OR recent.settled_at >= ?))`, cutoff).
		Scan(&result.Receipts); err != nil {
		return PruneResult{}, err
	}
	res, err := tx.Exec(
		`DELETE FROM messages
		 WHERE (NOT EXISTS (SELECT 1 FROM receipts any_receipt
		                    WHERE any_receipt.message_seq = messages.seq)
		        AND ts < ?)
		    OR (EXISTS (SELECT 1 FROM receipts any_receipt
		                WHERE any_receipt.message_seq = messages.seq)
		        AND NOT EXISTS (SELECT 1 FROM receipts open
		                        WHERE open.message_seq = messages.seq
		                          AND open.state IN ('pending','offered'))
		        AND NOT EXISTS (SELECT 1 FROM receipts recent
		                        WHERE recent.message_seq = messages.seq
		                          AND (recent.settled_at IS NULL OR recent.settled_at >= ?)))`, cutoff, cutoff)
	if err != nil {
		return PruneResult{}, err
	}
	result.Messages, _ = res.RowsAffected()
	res, err = tx.Exec(
		`DELETE FROM batch_deliveries
		 WHERE state IN ('completed','superseded')
		   AND COALESCE(completed_at, superseded_at, created_at) < ?
		   AND NOT EXISTS (SELECT 1 FROM receipts r
		                   WHERE r.delivery_id = batch_deliveries.delivery_id)`, cutoff)
	if err != nil {
		return PruneResult{}, err
	}
	result.Deliveries, _ = res.RowsAffected()
	if _, err := tx.Exec(
		`INSERT INTO audit_events(action, reason) VALUES('prune', ?)`,
		fmt.Sprintf("before=%s messages=%d receipts=%d deliveries=%d",
			cutoff, result.Messages, result.Receipts, result.Deliveries)); err != nil {
		return PruneResult{}, err
	}
	return result, tx.Commit()
}

func (b *Bus) Mint(name string) (_ string, err error) {
	defer func() { err = mapStorageError(err) }()
	if !nameRE.MatchString(name) {
		return "", ErrInvalidName
	}
	tx, err := b.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var state string
	var priorToken sql.NullString
	err = tx.QueryRow(`SELECT state, token_hash FROM mailboxes WHERE name = ?`, name).Scan(&state, &priorToken)
	action := "mint"
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(`INSERT INTO mailboxes(name, state) VALUES(?, 'active')`, name); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case state == "retired":
		return "", ErrRetiredIdentity
	case state == "reserved":
		if _, err := tx.Exec(`UPDATE mailboxes SET state = 'active' WHERE name = ?`, name); err != nil {
			return "", err
		}
	case priorToken.Valid:
		action = "rekey"
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`UPDATE mailboxes
		 SET token_hash = ?,
		     credential_generation = credential_generation + 1,
		     last_seen = strftime('%Y-%m-%dT%H:%M:%fZ','now')
		 WHERE name = ?`,
		hashToken(token), name); err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO audit_events(action, mailbox_name, reason) VALUES(?,?,?)`,
		action, name, "credential issued"); err != nil {
		return "", err
	}
	return token, tx.Commit()
}

func (b *Bus) Authenticate(token string) (string, error) {
	principal, err := b.AuthenticatePrincipal(token)
	return principal.Name, err
}

// AuthenticatePrincipal resolves an active bearer credential to a non-secret
// principal snapshot. The generation changes whenever Mint rotates the
// credential, allowing parked requests to detect revocation without retaining
// the bearer token.
func (b *Bus) AuthenticatePrincipal(token string) (AuthenticatedPrincipal, error) {
	var principal AuthenticatedPrincipal
	err := b.db.QueryRow(
		`SELECT name, credential_generation
		 FROM mailboxes WHERE token_hash = ? AND state = 'active'`,
		hashToken(token)).Scan(&principal.Name, &principal.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthenticatedPrincipal{}, ErrBadToken
	}
	return principal, err
}

// ValidatePrincipal confirms that a previously authenticated credential
// generation is still active. It deliberately accepts no bearer token so raw
// credentials cannot leak through parked-request state or tool output.
func (b *Bus) ValidatePrincipal(principal AuthenticatedPrincipal) error {
	var exists int
	err := b.db.QueryRow(
		`SELECT 1 FROM mailboxes
		 WHERE name = ? AND credential_generation = ? AND state = 'active'`,
		principal.Name, principal.Generation).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBadToken
	}
	return err
}

type DeadLetter struct {
	MessageID string `json:"message_id"`
	Reason    string `json:"reason"`
	TS        string `json:"ts"`
}

type AuditEvent struct {
	ID          int64   `json:"id"`
	Action      string  `json:"action"`
	MailboxName *string `json:"mailbox_name,omitempty"`
	MessageID   *string `json:"message_id,omitempty"`
	SenderName  *string `json:"sender_name,omitempty"`
	Reason      string  `json:"reason"`
	TS          string  `json:"ts"`
}

func (b *Bus) AuditEvents(afterID int64, limit int) ([]AuditEvent, error) {
	if afterID < 0 || limit < 1 || limit > maxAuditPageSize {
		return nil, ErrInvalidPagination
	}
	rows, err := b.db.Query(
		`SELECT id, action, mailbox_name, message_id, sender_name, reason, ts
		 FROM audit_events WHERE id > ? ORDER BY id LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []AuditEvent
	for rows.Next() {
		var event AuditEvent
		var mailboxName, messageID, senderName sql.NullString
		if err := rows.Scan(&event.ID, &event.Action, &mailboxName, &messageID, &senderName, &event.Reason, &event.TS); err != nil {
			return nil, err
		}
		if mailboxName.Valid {
			event.MailboxName = &mailboxName.String
		}
		if messageID.Valid {
			event.MessageID = &messageID.String
		}
		if senderName.Valid {
			event.SenderName = &senderName.String
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func validateAuditReason(reason string) error {
	if strings.TrimSpace(reason) == "" || len(reason) > maxAuditReasonBytes {
		return ErrInvalidReason
	}
	return nil
}

func (b *Bus) DeadLetters(name string) ([]DeadLetter, error) {
	rows, err := b.db.Query(
		`SELECT message_id, reason, ts FROM audit_events
		 WHERE mailbox_name = ? AND message_id IS NOT NULL
		   AND action IN ('skip','retire_receipt')
		 ORDER BY id`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []DeadLetter
	for rows.Next() {
		var d DeadLetter
		if err := rows.Scan(&d.MessageID, &d.Reason, &d.TS); err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}

type RosterEntry struct {
	Name     string `json:"name"`
	Waiting  bool   `json:"waiting"`
	LastSeen string `json:"last_seen,omitempty"`
}

type BacklogMailbox struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	Receipts    int64  `json:"receipts"`
	Bytes       int64  `json:"bytes"`
	MaxAttempts int64  `json:"max_attempts"`
}

type BacklogReport struct {
	TotalReceipts int64            `json:"total_receipts"`
	TotalBytes    int64            `json:"total_bytes"`
	Mailboxes     []BacklogMailbox `json:"mailboxes"`
}

func (b *Bus) Backlog() (BacklogReport, error) {
	rows, err := b.db.Query(
		`SELECT mb.name, mb.state, COUNT(r.message_seq),
		        COALESCE(SUM(m.encoded_bytes), 0), COALESCE(MAX(r.attempts), 0)
		 FROM mailboxes mb
		 LEFT JOIN receipts r ON r.mailbox_name = mb.name AND r.state IN ('pending','offered')
		 LEFT JOIN messages m ON m.seq = r.message_seq
		 WHERE mb.state IN ('active','reserved')
		 GROUP BY mb.name, mb.state ORDER BY mb.name`)
	if err != nil {
		return BacklogReport{}, err
	}
	defer rows.Close()
	var report BacklogReport
	for rows.Next() {
		var mailbox BacklogMailbox
		if err := rows.Scan(&mailbox.Name, &mailbox.State, &mailbox.Receipts, &mailbox.Bytes, &mailbox.MaxAttempts); err != nil {
			return BacklogReport{}, err
		}
		report.TotalReceipts += mailbox.Receipts
		report.TotalBytes += mailbox.Bytes
		report.Mailboxes = append(report.Mailboxes, mailbox)
	}
	return report, rows.Err()
}

// Activity returns a body-free traffic and delivery summary. Durable counters
// are updated in the same transactions as their delivery transitions, so
// pruning terminal payloads cannot make historical usage decrease.
func (b *Bus) Activity() (ActivityReport, error) {
	var report ActivityReport
	tx, err := b.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ActivityReport{}, err
	}
	defer tx.Rollback()
	if err := tx.QueryRow(
		`SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now'), applied_at
		 FROM schema_migrations WHERE version = 3`).
		Scan(&report.AsOf, &report.TrackingStartedAt); err != nil {
		return ActivityReport{}, err
	}
	if err := tx.QueryRow(
		`SELECT
		 COALESCE((SELECT SUM(messages_sent) FROM mailbox_activity), 0),
		 COALESCE((SELECT SUM(receipts_enqueued) FROM mailbox_activity), 0),
		 COALESCE((SELECT SUM(receipts_acked) FROM mailbox_activity), 0),
		 COALESCE((SELECT SUM(receipts_dead) FROM mailbox_activity), 0),
		 COALESCE((SELECT SUM(offer_attempts) FROM mailbox_activity), 0),
		 (SELECT COUNT(*) FROM receipts WHERE state = 'pending'),
		 (SELECT COUNT(*) FROM receipts WHERE state = 'offered'),
		 (SELECT COUNT(*) FROM batch_deliveries WHERE state = 'outstanding'),
		 COALESCE((SELECT MAX(attempts) FROM receipts
		           WHERE state IN ('pending','offered')), 0)`).Scan(
		&report.SinceTracking.MessagesSent,
		&report.SinceTracking.ReceiptsEnqueued,
		&report.SinceTracking.ReceiptsAcked,
		&report.SinceTracking.ReceiptsDead,
		&report.SinceTracking.OfferAttempts,
		&report.Current.PendingReceipts,
		&report.Current.OfferedReceipts,
		&report.Current.OutstandingDeliveries,
		&report.Current.MaxAttempts,
	); err != nil {
		return ActivityReport{}, err
	}
	rows, err := tx.Query(
		`SELECT mb.name, mb.state, COALESCE(mb.last_seen, ''),
		        COALESCE(a.messages_sent, 0), COALESCE(a.receipts_enqueued, 0),
		        COALESCE(a.receipts_acked, 0), COALESCE(a.receipts_dead, 0),
		        COALESCE(a.offer_attempts, 0),
		        (SELECT COUNT(*) FROM receipts r
		         WHERE r.mailbox_name = mb.name AND r.state = 'pending'),
		        (SELECT COUNT(*) FROM receipts r
		         WHERE r.mailbox_name = mb.name AND r.state = 'offered'),
		        CASE WHEN EXISTS(
		          SELECT 1 FROM batch_deliveries d
		          WHERE d.mailbox_name = mb.name AND d.state = 'outstanding'
		        ) THEN 1 ELSE 0 END,
		        COALESCE((SELECT MAX(r.attempts) FROM receipts r
		                  WHERE r.mailbox_name = mb.name
		                    AND r.state IN ('pending','offered')), 0),
		        COALESCE(a.last_sent_at, ''), COALESCE(a.last_enqueued_at, ''),
		        COALESCE(a.last_offered_at, ''), COALESCE(a.last_acked_at, ''),
		        COALESCE(a.last_dead_at, '')
		 FROM mailboxes mb
		 LEFT JOIN mailbox_activity a ON a.mailbox_name = mb.name
		 ORDER BY mb.name LIMIT ?`, maxActivityMailboxes+1)
	if err != nil {
		return ActivityReport{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var mailbox ActivityMailbox
		var outstanding int64
		if err := rows.Scan(
			&mailbox.Name, &mailbox.State, &mailbox.LastSeen,
			&mailbox.SinceTracking.MessagesSent, &mailbox.SinceTracking.ReceiptsEnqueued,
			&mailbox.SinceTracking.ReceiptsAcked, &mailbox.SinceTracking.ReceiptsDead,
			&mailbox.SinceTracking.OfferAttempts,
			&mailbox.Current.PendingReceipts,
			&mailbox.Current.OfferedReceipts, &outstanding, &mailbox.Current.MaxAttempts,
			&mailbox.LastSentAt, &mailbox.LastEnqueuedAt,
			&mailbox.LastOfferedAt, &mailbox.LastAckedAt, &mailbox.LastDeadAt,
		); err != nil {
			return ActivityReport{}, err
		}
		mailbox.Current.OutstandingDeliveries = outstanding
		if len(report.Mailboxes) == maxActivityMailboxes {
			report.Truncated = true
			continue
		}
		report.Mailboxes = append(report.Mailboxes, mailbox)
	}
	if err := rows.Close(); err != nil {
		return ActivityReport{}, err
	}
	if err := rows.Err(); err != nil {
		return ActivityReport{}, err
	}
	if err := tx.Commit(); err != nil {
		return ActivityReport{}, err
	}
	return report, nil
}

// RecentRoutes returns one stable newest-first page from retained messages.
// beforeSeq is exclusive; zero starts at the newest retained message.
func (b *Bus) RecentRoutes(beforeSeq int64, limit int) ([]RecentRoute, error) {
	if beforeSeq < 0 || limit < 1 || limit > maxRecentRoutes {
		return nil, ErrInvalidPagination
	}
	query := `WITH recent AS MATERIALIZED (
		 SELECT seq, message_id, from_name, to_name, ts
		 FROM messages`
	args := make([]any, 0, 2)
	if beforeSeq > 0 {
		query += ` WHERE seq < ?`
		args = append(args, beforeSeq)
	}
	query += ` ORDER BY seq DESC LIMIT ?
		)
		SELECT m.seq, m.message_id, m.from_name, m.to_name, m.ts,
		        COALESCE(SUM(CASE WHEN r.state = 'pending' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN r.state = 'offered' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN r.state = 'acked' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN r.state = 'dead' THEN 1 ELSE 0 END), 0)
		 FROM recent m
		 LEFT JOIN receipts r ON r.message_seq = m.seq`
	query += `
		 GROUP BY m.seq, m.message_id, m.from_name, m.to_name, m.ts
		 ORDER BY m.seq DESC`
	args = append(args, limit)
	rows, err := b.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var routes []RecentRoute
	for rows.Next() {
		var route RecentRoute
		if err := rows.Scan(
			&route.Seq, &route.MessageID, &route.From, &route.To, &route.TS,
			&route.Receipts.Pending, &route.Receipts.Offered,
			&route.Receipts.Acked, &route.Receipts.Dead,
		); err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, rows.Err()
}

// MessageContent retrieves one retained message for explicit operator
// inspection. Authorization remains the responsibility of the calling adapter.
func (b *Bus) MessageContent(messageID string) (Message, error) {
	if !messageIDRE.MatchString(messageID) {
		return Message{}, ErrMessageNotFound
	}
	var message Message
	var data, replyTo sql.NullString
	err := b.db.QueryRow(
		`SELECT seq, message_id, from_name, to_name, ts, body, data, reply_to
		 FROM messages WHERE message_id = ?`, messageID).Scan(
		&message.Seq, &message.MessageID, &message.From, &message.To, &message.TS,
		&message.Body, &data, &replyTo,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Message{}, ErrMessageNotFound
	}
	if err != nil {
		return Message{}, err
	}
	if data.Valid {
		message.Data = json.RawMessage(data.String)
	}
	if replyTo.Valid {
		message.ReplyTo = &replyTo.String
	}
	return message, nil
}

func (b *Bus) Roster() ([]RosterEntry, error) {
	rows, err := b.db.Query(
		`SELECT name, COALESCE(last_seen, '') FROM mailboxes WHERE state = 'active' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []RosterEntry
	for rows.Next() {
		var e RosterEntry
		if err := rows.Scan(&e.Name, &e.LastSeen); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	for i := range entries {
		entries[i].Waiting = len(b.waiters[entries[i].Name]) > 0
	}
	b.mu.Unlock()
	return entries, nil
}

func (b *Bus) Ready() (err error) {
	defer func() { err = mapStorageError(err) }()
	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`UPDATE mailboxes SET last_seen = last_seen WHERE 0`)
	return err
}

func activateMailbox(tx *sql.Tx, name string) error {
	state, err := mailboxState(tx, name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.Exec(
			`INSERT INTO mailboxes(name, state, last_seen)
			 VALUES(?, 'active', strftime('%Y-%m-%dT%H:%M:%fZ','now'))`, name)
		return err
	case err != nil:
		return err
	case state == "retired":
		return ErrRetiredIdentity
	case state == "reserved":
		_, err = tx.Exec(
			`UPDATE mailboxes SET state = 'active', last_seen = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE name = ?`, name)
		return err
	default:
		_, err = tx.Exec(
			`UPDATE mailboxes SET last_seen = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE name = ?`, name)
		return err
	}
}

func requireActiveMailbox(tx *sql.Tx, name string) error {
	state, err := mailboxState(tx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDeliveryConflict
	}
	if err != nil {
		return err
	}
	if state == "retired" {
		return ErrRetiredIdentity
	}
	if state != "active" {
		return ErrDeliveryConflict
	}
	return nil
}

func mailboxState(tx *sql.Tx, name string) (string, error) {
	var state string
	err := tx.QueryRow(`SELECT state FROM mailboxes WHERE name = ?`, name).Scan(&state)
	return state, err
}

func loadMessage(tx *sql.Tx, seq int64) (Message, error) {
	var m Message
	var data sql.NullString
	var replyTo sql.NullString
	err := tx.QueryRow(
		`SELECT seq, message_id, from_name, to_name, ts, body, data, reply_to
		 FROM messages WHERE seq = ?`, seq).
		Scan(&m.Seq, &m.MessageID, &m.From, &m.To, &m.TS, &m.Body, &data, &replyTo)
	if err != nil {
		return Message{}, err
	}
	if data.Valid {
		m.Data = json.RawMessage(data.String)
	}
	if replyTo.Valid {
		m.ReplyTo = &replyTo.String
	}
	return m, nil
}

func loadPendingMessages(tx *sql.Tx, name string) ([]Message, error) {
	return loadReceiptMessages(tx,
		`SELECT m.seq, m.message_id, m.from_name, m.to_name, m.ts, m.body, m.data, m.reply_to
		 FROM receipts r JOIN messages m ON m.seq = r.message_seq
		 WHERE r.mailbox_name = ? AND r.state = 'pending'
		 ORDER BY m.seq ASC LIMIT ?`, name, batchLimit)
}

func loadDeliveryMessages(tx *sql.Tx, name, deliveryID string) ([]Message, error) {
	return loadReceiptMessages(tx,
		`SELECT m.seq, m.message_id, m.from_name, m.to_name, m.ts, m.body, m.data, m.reply_to
		 FROM receipts r JOIN messages m ON m.seq = r.message_seq
		 WHERE r.mailbox_name = ? AND r.delivery_id = ? AND r.state = 'offered'
		 ORDER BY m.seq ASC`, name, deliveryID)
}

func loadReceiptMessages(tx *sql.Tx, query string, args ...any) ([]Message, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []Message
	for rows.Next() {
		var m Message
		var data sql.NullString
		var replyTo sql.NullString
		if err := rows.Scan(&m.Seq, &m.MessageID, &m.From, &m.To, &m.TS, &m.Body, &data, &replyTo); err != nil {
			return nil, err
		}
		if data.Valid {
			m.Data = json.RawMessage(data.String)
		}
		if replyTo.Valid {
			m.ReplyTo = &replyTo.String
		}
		candidate := append(messages, m)
		// Reserve the complete largest delivery wrapper used by the MCP adapter;
		// plain HTTP's delivery object is smaller. This keeps either serialized
		// delivery within maxBatchBytes instead of limiting only its inner array.
		wire := struct {
			Mail     bool      `json:"mail"`
			Delivery *Delivery `json:"delivery"`
		}{
			Mail: true,
			Delivery: &Delivery{
				ID:         "dlv_ffffffffffffffffffffffffffffffff",
				Redelivery: false,
				Messages:   candidate,
			},
		}
		encoded, err := json.Marshal(wire)
		if err != nil {
			return nil, err
		}
		if len(messages) > 0 && len(encoded)+1 > maxBatchBytes { // HTTP JSON encoder newline
			break
		}
		messages = candidate
	}
	return messages, rows.Err()
}

func (b *Bus) register(name string) (chan struct{}, error) {
	ch := make(chan struct{})
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.waiters[name]) >= maxWaitersPerMailbox {
		return nil, ErrWaiterLimit
	}
	if b.waiterCount >= maxWaiters {
		return nil, ErrWaiterLimit
	}
	b.waiters[name] = append(b.waiters[name], ch)
	b.waiterCount++
	return ch, nil
}

func (b *Bus) unregister(name string, ch chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ws := b.waiters[name]
	for i, w := range ws {
		if w == ch {
			b.waiters[name] = append(ws[:i], ws[i+1:]...)
			b.waiterCount--
			if len(b.waiters[name]) == 0 {
				delete(b.waiters, name)
			}
			return
		}
	}
}

func (b *Bus) wake(to string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if to == "*" {
		for name, ws := range b.waiters {
			for _, ch := range ws {
				close(ch)
			}
			delete(b.waiters, name)
		}
		b.waiterCount = 0
		return
	}
	b.waiterCount -= len(b.waiters[to])
	for _, ch := range b.waiters[to] {
		close(ch)
	}
	delete(b.waiters, to)
}

func newID(prefix string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(buf), nil
}

func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "abt_" + hex.EncodeToString(buf), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
