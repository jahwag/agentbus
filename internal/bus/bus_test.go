package bus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T) *Bus {
	t.Helper()
	b, err := Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestOpenRejectsLegacyCursorSchemaBeforeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE messages(seq INTEGER PRIMARY KEY, body TEXT);
		CREATE TABLE identities(name TEXT PRIMARY KEY, cursor INTEGER);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); !errors.Is(err, ErrLegacySchema) {
		t.Fatalf("legacy cursor database must be rejected explicitly, got %v", err)
	}
	db, err = sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var created int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mailboxes'`).Scan(&created); err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatal("legacy refusal mutated the database before failing")
	}
}

func TestOpenRejectsUnknownMigrationBeforeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, checksum TEXT NOT NULL);
		INSERT INTO schema_migrations(version, checksum) VALUES(99, 'future');`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("newer database must be rejected")
	}
	db, err = sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var created int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mailboxes'`).Scan(&created); err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatal("newer-schema refusal applied old migrations before failing")
	}
}

func TestMigrationFiveAddsExternalPrincipalSchema(t *testing.T) {
	b := open(t)
	var kind string
	if err := b.db.QueryRow(
		`SELECT principal_kind FROM mailboxes LIMIT 1`,
	).Scan(&kind); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("principal_kind column unavailable: %v", err)
	}
	var version int
	if err := b.db.QueryRow(
		`SELECT version FROM schema_migrations WHERE version=5`,
	).Scan(&version); err != nil || version != 5 {
		t.Fatalf("migration 5 missing: version=%d err=%v", version, err)
	}
	if _, err := b.db.Exec(
		`INSERT INTO external_identities(issuer,subject,mailbox_name)
		 VALUES('issuer','subject','missing')`,
	); err == nil {
		t.Fatal("external identity foreign key was not enforced")
	}
}

func TestMigrationFiveUpgradesPopulatedVersionFourDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations[:4] {
		if _, err := db.Exec(migration.sql); err != nil {
			t.Fatal(err)
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256([]byte(migration.sql)))
		if _, err := db.Exec(
			`INSERT INTO schema_migrations(version, checksum) VALUES(?, ?)`,
			migration.version,
			checksum,
		); err != nil {
			t.Fatal(err)
		}
	}
	const token = "pre-migration-agent-token"
	if _, err := db.Exec(`
		INSERT INTO mailboxes(name,state,token_hash,credential_generation)
		VALUES('worker','active',?,7);
		INSERT INTO mailboxes(name,state)
		VALUES('recipient','active');
		INSERT INTO messages(
			message_id,from_name,to_name,body,encoded_bytes,client_message_id
		) VALUES(
			'msg_00000000000000000000000000000001',
			'worker','recipient','retained before migration',25,'pre-migration-send'
		);
		INSERT INTO receipts(mailbox_name,message_seq,state)
		SELECT 'recipient',seq,'pending' FROM messages`,
		hashToken(token),
	); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	principal, err := b.AuthenticatePrincipal(token)
	if err != nil || principal.Name != "worker" || principal.Kind != "agent" ||
		principal.Generation != 7 {
		t.Fatalf("migrated principal=%+v error=%v", principal, err)
	}
	delivery, err := b.NextDelivery("recipient")
	if err != nil || delivery == nil || len(delivery.Messages) != 1 ||
		delivery.Messages[0].Body != "retained before migration" {
		t.Fatalf("migrated delivery=%+v error=%v", delivery, err)
	}
	if err := b.BindExternalIdentity(
		"worker",
		"agent",
		"https://issuer.example.test",
		"worker-subject",
	); err != nil {
		t.Fatal(err)
	}
	external, err := b.AuthenticateExternal(
		"https://issuer.example.test",
		"worker-subject",
		time.Now().Add(time.Hour),
	)
	if err != nil || external.Name != "worker" || external.Kind != "agent" {
		t.Fatalf("migrated external principal=%+v error=%v", external, err)
	}
}

func TestExternalIdentityBindingSeparatesAgentsAndOperators(t *testing.T) {
	b := open(t)
	expires := time.Now().Add(time.Hour)
	if err := b.BindExternalIdentity("human.alex", "operator", "https://edge.example", "human-1"); err != nil {
		t.Fatal(err)
	}
	operator, err := b.AuthenticateExternal("https://edge.example", "human-1", expires)
	if err != nil || operator.Name != "human.alex" || operator.Kind != "operator" {
		t.Fatalf("operator authentication = %+v, %v", operator, err)
	}
	if err := b.BindExternalIdentity("worker", "agent", "https://login.example", "agent-1"); err != nil {
		t.Fatal(err)
	}
	agent, err := b.AuthenticateExternal("https://login.example", "agent-1", expires)
	if err != nil || agent.Kind != "agent" {
		t.Fatalf("agent authentication = %+v, %v", agent, err)
	}
	if err := b.BindExternalIdentity("other", "agent", "https://edge.example", "human-1"); !errors.Is(err, ErrExternalIdentityInUse) {
		t.Fatalf("duplicate external identity error = %v", err)
	}
	if err := b.UnbindExternalIdentity("https://edge.example", "human-1"); err != nil {
		t.Fatal(err)
	}
	if err := b.ValidatePrincipal(operator); !errors.Is(err, ErrBadToken) {
		t.Fatalf("unbound operator session remained valid: %v", err)
	}
}

func TestPrincipalKindsAreImmutableAndOperatorsDisallowNativeCredentials(t *testing.T) {
	b := open(t)
	token, err := b.Mint("human.alex")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.BindExternalIdentity(
		"human.alex",
		"operator",
		"https://edge.example",
		"human-1",
	); !errors.Is(err, ErrPrincipalKindConflict) {
		t.Fatalf("agent mailbox changed to operator: %v", err)
	}
	if _, err := b.AuthenticatePrincipal(token); err != nil {
		t.Fatalf("failed kind change revoked valid agent credential: %v", err)
	}
	if err := b.BindExternalIdentity(
		"operator.alex",
		"operator",
		"https://edge.example",
		"operator-1",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Mint("operator.alex"); !errors.Is(err, ErrInvalidPrincipalKind) {
		t.Fatalf("operator mailbox received a native credential: %v", err)
	}

	// Defense in depth for any pre-release database created before operators
	// were forbidden from retaining native credentials.
	const legacyOperatorToken = "legacy-operator-token"
	if _, err := b.db.Exec(
		`UPDATE mailboxes SET token_hash=? WHERE name='operator.alex'`,
		hashToken(legacyOperatorToken),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AuthenticatePrincipal(legacyOperatorToken); err != nil {
		t.Fatalf("test setup did not create legacy operator credential: %v", err)
	}
	if err := b.UnbindExternalIdentity("https://edge.example", "operator-1"); err != nil {
		t.Fatal(err)
	}
	if err := b.BindExternalIdentity(
		"operator.alex",
		"operator",
		"https://edge.example",
		"operator-1",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AuthenticatePrincipal(legacyOperatorToken); !errors.Is(err, ErrBadToken) {
		t.Fatalf("legacy operator credential survived rebinding: %v", err)
	}
}

func TestReservedAgentBindingActivatesWithoutChangingKind(t *testing.T) {
	b := open(t)
	if _, err := b.Mint("sender"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("sender", "future-agent", SendOpts{
		Body:            "reserved delivery",
		ClientMessageID: "reserve-agent",
		AllowNew:        true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindExternalIdentity(
		"future-agent",
		"agent",
		"https://login.example",
		"agent-1",
	); err != nil {
		t.Fatal(err)
	}
	principal, err := b.AuthenticateExternal(
		"https://login.example",
		"agent-1",
		time.Now().Add(time.Hour),
	)
	if err != nil || principal.Kind != "agent" {
		t.Fatalf("reserved agent did not activate: principal=%+v err=%v", principal, err)
	}
	delivery, err := b.NextDelivery("future-agent")
	if err != nil || len(delivery.Messages) != 1 {
		t.Fatalf("reserved delivery was stranded: delivery=%+v err=%v", delivery, err)
	}
}

func TestReservedMailboxCanBeReclaimedAsOperatorWithoutStrandedReceipts(t *testing.T) {
	b := open(t)
	if _, err := b.Mint("sender"); err != nil {
		t.Fatal(err)
	}
	message, err := b.Send("sender", "future-operator", SendOpts{
		Body:            "reserved delivery",
		ClientMessageID: "reserve-operator",
		AllowNew:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.BindExternalIdentity(
		"future-operator",
		"operator",
		"https://edge.example",
		"operator-1",
	); err != nil {
		t.Fatal(err)
	}
	operator, err := b.AuthenticateExternal(
		"https://edge.example",
		"operator-1",
		time.Now().Add(time.Hour),
	)
	if err != nil || operator.Kind != "operator" {
		t.Fatalf("reclaimed operator = %+v, %v", operator, err)
	}
	var receipts int
	if err := b.db.QueryRow(
		`SELECT COUNT(*) FROM receipts WHERE mailbox_name='future-operator'`,
	).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 0 {
		t.Fatalf("operator reclaim stranded %d receipts", receipts)
	}
	if _, err := b.MessageContent(message.MessageID); err != nil {
		t.Fatalf("operator reclaim unexpectedly erased retained routing history: %v", err)
	}
	events, err := b.AuditEvents(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var audited bool
	for _, event := range events {
		if event.Action == "bind_external_identity" &&
			event.MailboxName != nil && *event.MailboxName == "future-operator" &&
			strings.Contains(event.Reason, "discarded_receipts=1") {
			audited = true
		}
	}
	if !audited {
		t.Fatalf("operator reclaim did not audit discarded receipt count: %+v", events)
	}
}

func TestOperatorMailboxesAreNotAgentRecipients(t *testing.T) {
	b := open(t)
	b.backlogLimits.mailboxReceipts = 1
	if _, err := b.Mint("worker"); err != nil {
		t.Fatal(err)
	}
	if err := b.BindExternalIdentity(
		"human.alex",
		"operator",
		"https://edge.example",
		"human-1",
	); err != nil {
		t.Fatal(err)
	}

	roster, err := b.Roster()
	if err != nil {
		t.Fatal(err)
	}
	if len(roster) != 1 || roster[0].Name != "worker" {
		t.Fatalf("operator leaked into agent roster: %+v", roster)
	}
	operatorReply, err := b.Send("worker", "human.alex", SendOpts{
		Body:            "operator-visible reply",
		ClientMessageID: "operator-direct",
	})
	if err != nil {
		t.Fatalf("direct operator reply failed: %v", err)
	}
	for i := range 2 {
		if _, err := b.Send("worker", "*", SendOpts{
			Body:            "broadcast",
			ClientMessageID: fmt.Sprintf("operator-broadcast-%d", i),
		}); err != nil {
			t.Fatalf("broadcast %d consumed operator backlog: %v", i, err)
		}
	}
	var operatorReceipts int
	if err := b.db.QueryRow(
		`SELECT COUNT(*) FROM receipts WHERE mailbox_name='human.alex'`,
	).Scan(&operatorReceipts); err != nil {
		t.Fatal(err)
	}
	if operatorReceipts != 0 {
		t.Fatalf("operator received %d agent delivery receipts", operatorReceipts)
	}
	routes, err := b.RecentRoutes(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var visible bool
	for _, route := range routes {
		visible = visible || route.MessageID == operatorReply.MessageID
	}
	conversation, err := b.Conversation(operatorReply.MessageID, 10)
	if err != nil || len(conversation.Messages) != 1 {
		t.Fatalf("operator reply was not retained for UI views: %+v, %v", conversation, err)
	}
	if !visible {
		t.Fatalf("operator reply missing from recent routes: %+v", routes)
	}
	if _, err := b.Prune(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.MessageContent(operatorReply.MessageID); !errors.Is(err, ErrMessageNotFound) {
		t.Fatalf("receipt-free operator reply survived retention pruning: %v", err)
	}
}

func TestSendAsOperatorIsDirectAttributedAndAudited(t *testing.T) {
	b := open(t)
	if err := b.BindExternalIdentity("human.alex", "operator", "https://edge.example", "human-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Mint("worker"); err != nil {
		t.Fatal(err)
	}
	operator, err := b.AuthenticateExternal(
		"https://edge.example",
		"human-1",
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	message, err := b.SendAsOperator(operator, "worker", SendOpts{
		Body:            "please report status",
		ClientMessageID: "server-generated-test-id",
		AllowNew:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if message.From != "human.alex" || message.To != "worker" {
		t.Fatalf("operator attribution = %+v", message)
	}
	if _, err := b.SendAsOperator(operator, "*", SendOpts{
		Body: "broadcast", ClientMessageID: "forbidden-broadcast",
	}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("operator broadcast error = %v", err)
	}
	events, err := b.AuditEvents(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, event := range events {
		if event.Action != "operator_send" {
			continue
		}
		found = true
		if event.SenderName == nil || *event.SenderName != "human.alex" ||
			event.MailboxName == nil || *event.MailboxName != "worker" ||
			event.MessageID == nil || *event.MessageID != message.MessageID ||
			strings.Contains(event.Reason, message.Body) {
			t.Fatalf("unsafe operator audit event = %+v", event)
		}
	}
	if !found {
		t.Fatal("operator_send audit event missing")
	}
}

func TestConversationIsBoundedAndReportsPrunedParent(t *testing.T) {
	b := open(t)
	root, err := b.Send("amara", "athena", SendOpts{
		Body: "root", ClientMessageID: "conversation-root", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	parent := root.MessageID
	for i := 0; i < 110; i++ {
		from, to := "athena", "amara"
		if i%2 == 1 {
			from, to = to, from
		}
		message, err := b.Send(from, to, SendOpts{
			Body:            fmt.Sprintf("reply-%d", i),
			ReplyTo:         &parent,
			ClientMessageID: fmt.Sprintf("conversation-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		parent = message.MessageID
	}
	conversation, err := b.Conversation(parent, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(conversation.Messages) != 100 || !conversation.Truncated {
		t.Fatalf("conversation bounds = %d truncated=%v", len(conversation.Messages), conversation.Truncated)
	}

	child := conversation.Messages[1]
	if _, err := b.db.Exec(`DELETE FROM messages WHERE message_id=?`, conversation.Messages[0].MessageID); err != nil {
		t.Fatal(err)
	}
	afterPrune, err := b.Conversation(child.MessageID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if afterPrune.MissingParent == "" || len(afterPrune.Messages) == 0 ||
		afterPrune.Messages[0].MessageID != child.MessageID {
		t.Fatalf("pruned-parent conversation = %+v", afterPrune)
	}
}

func TestConversationBoundsWideReplyTreesInsideRecursiveWalk(t *testing.T) {
	b := open(t)
	root, err := b.Send("amara", "athena", SendOpts{
		Body: "root", ClientMessageID: "wide-conversation-root", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := b.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < 2_000; i++ {
		messageID := fmt.Sprintf("msg_%032x", i+1)
		if _, err := tx.Exec(
			`INSERT INTO messages(
				message_id,from_name,to_name,body,reply_to,encoded_bytes,client_message_id
			 ) VALUES(?,?,?,?,?,?,?)`,
			messageID,
			"athena",
			"amara",
			"wide reply",
			root.MessageID,
			64,
			fmt.Sprintf("wide-conversation-%d", i),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	conversation, err := b.Conversation(root.MessageID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(conversation.Messages) != 100 || !conversation.Truncated {
		t.Fatalf(
			"wide conversation bounds = %d truncated=%v",
			len(conversation.Messages),
			conversation.Truncated,
		)
	}
}

func TestOpenRefusesSecondOwnerOfDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	second, err := Open(path)
	if second != nil {
		second.Close()
	}
	if !errors.Is(err, ErrDatabaseInUse) {
		t.Fatalf("second process owner must be refused, got %v", err)
	}
}

func TestOpenRefusesHardlinkAliasOfOwnedDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	alias := filepath.Join(dir, "alias.db")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	second, err := Open(alias)
	if second != nil {
		second.Close()
	}
	if !errors.Is(err, ErrDatabaseInUse) {
		t.Fatalf("hardlink alias must not bypass single-daemon ownership, got %v", err)
	}
}

func TestInMemoryBusesArePrivateAndIsolated(t *testing.T) {
	first, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := first.Send("codex", "claude", SendOpts{
		Body: "belongs to first", ClientMessageID: "private-memory", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	if d, err := second.NextDelivery("claude"); err != nil || d != nil {
		t.Fatalf("second in-memory bus observed first bus state: delivery=%+v err=%v", d, err)
	}
}

func TestOpenCapsSQLiteDatabaseSize(t *testing.T) {
	b := open(t)
	var pageSize, maxPages int64
	if err := b.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	if err := b.db.QueryRow(`PRAGMA max_page_count`).Scan(&maxPages); err != nil {
		t.Fatal(err)
	}
	if got := pageSize * maxPages; got > maxDatabaseBytes || maxDatabaseBytes-got >= pageSize {
		t.Fatalf("SQLite hard cap = %d bytes (%d x %d), want largest page multiple <= %d", got, pageSize, maxPages, maxDatabaseBytes)
	}
}

func TestSQLiteFullMapsToBacklogLimit(t *testing.T) {
	b := open(t)
	var pages int64
	if err := b.db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if err := b.db.QueryRow(fmt.Sprintf(`PRAGMA max_page_count = %d`, pages)).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	_, err := b.Send("codex", "claude", SendOpts{
		Body: strings.Repeat("x", 60*1024), ClientMessageID: "sqlite-full", AllowNew: true,
	})
	if !errors.Is(err, ErrBacklogLimit) {
		t.Fatalf("SQLite FULL must map to durable backlog limit, got %v", err)
	}
}

func TestOpenRefusesDatabasePathAliases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	aliases := map[string]func(string, string) error{
		"symlink":  os.Symlink,
		"hardlink": os.Link,
	}
	for name, link := range aliases {
		t.Run(name, func(t *testing.T) {
			alias := filepath.Join(dir, name+".db")
			if err := link(path, alias); err != nil {
				t.Fatal(err)
			}
			second, err := Open(alias)
			if second != nil {
				second.Close()
			}
			if !errors.Is(err, ErrDatabaseInUse) {
				t.Fatalf("database alias must share ownership lock, got %v", err)
			}
		})
	}
}

// Slice 7: skip dead-letters one poison message without touching later mail;
// retire is a terminal state that dead-letters outstanding mail and blocks
// further sends and waits.
func TestSkipAndRetire(t *testing.T) {
	b := open(t)

	if _, err := b.NextDelivery("claude"); err != nil {
		t.Fatal(err)
	}
	ok1, _ := b.Send("codex", "claude", SendOpts{Body: "ok-1", ClientMessageID: "skip-ok-1"})
	poison, _ := b.Send("codex", "claude", SendOpts{Body: "poison", ClientMessageID: "skip-poison"})
	ok2, _ := b.Send("codex", "claude", SendOpts{Body: "ok-2", ClientMessageID: "skip-ok-2"})

	d1, err := b.NextDelivery("claude")
	if err != nil || len(d1.Messages) != 3 {
		t.Fatalf("want 3 queued messages, got %+v, %v", d1, err)
	}

	if err := b.Skip("claude", "msg_nonexistent", "typo"); !errors.Is(err, ErrUnknownMessage) {
		t.Fatalf("skipping an unknown message must fail, got %v", err)
	}
	if err := b.Skip("claude", poison.MessageID, "crashes the agent"); err != nil {
		t.Fatal(err)
	}

	d2, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if d2.ID == d1.ID {
		t.Error("skip must invalidate the outstanding delivery so the batch is recomputed")
	}
	if !d2.Redelivery {
		t.Error("surviving receipts were already offered and must be marked as redelivery")
	}
	if len(d2.Messages) != 2 || d2.Messages[0].Seq != ok1.Seq || d2.Messages[1].Seq != ok2.Seq {
		t.Fatalf("skip must remove only the poison message, got %+v", d2.Messages)
	}
	if _, err := b.Ack("claude", d2.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := b.Send("codex", "claude", SendOpts{Body: "pinned forever", ClientMessageID: "retire-pinned"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Retire("claude", "vps decommissioned"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.NextDelivery("claude"); !errors.Is(err, ErrRetiredIdentity) {
		t.Fatalf("retired identity must not wait, got %v", err)
	}
	if _, err := b.Send("codex", "claude", SendOpts{Body: "x", ClientMessageID: "retire-rejected", AllowNew: true}); !errors.Is(err, ErrRetiredIdentity) {
		t.Fatalf("send to retired identity must fail even with AllowNew, got %v", err)
	}

	dls, err := b.DeadLetters("claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(dls) != 2 { // the skipped poison + the outstanding message at retire
		t.Fatalf("want 2 dead letters with reasons, got %+v", dls)
	}
}

func TestRetiredIdentityCannotActAsSender(t *testing.T) {
	b := open(t)

	if _, err := b.NextDelivery("codex"); err != nil {
		t.Fatal(err)
	}
	if err := b.Retire("codex", "agent decommissioned"); err != nil {
		t.Fatal(err)
	}
	_, err := b.Send("codex", "*", SendOpts{Body: "still here", ClientMessageID: "retired-send"})
	if !errors.Is(err, ErrRetiredIdentity) {
		t.Fatalf("retired sender must be rejected, got %v", err)
	}
}

func TestCompletedDeliveryAckRemainsIdempotentAfterMailboxRetirement(t *testing.T) {
	b := open(t)
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "processed", ClientMessageID: "ack-after-retire", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	want, err := b.Ack("claude", d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Retire("claude", "decommissioned after processing"); err != nil {
		t.Fatal(err)
	}
	got, err := b.Ack("claude", d.ID)
	if err != nil || got != want {
		t.Fatalf("lost ack response must remain retryable after retirement: got %d, %v", got, err)
	}
}

func TestDirectSelfSendIsRejected(t *testing.T) {
	b := open(t)

	_, err := b.Send("codex", "codex", SendOpts{
		Body: "feedback loop", ClientMessageID: "self-send",
	})
	if !errors.Is(err, ErrSelfSend) {
		t.Fatalf("direct self-send must be rejected, got %v", err)
	}
}

func TestPruneKeepsUnsettledReceipts(t *testing.T) {
	b := open(t)

	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "settled", ClientMessageID: "prune-settled", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "must survive", ClientMessageID: "prune-unsettled",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := b.Prune(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if result.Messages != 1 || result.Receipts != 1 {
		t.Fatalf("prune must remove only the settled obligation, got %+v", result)
	}
	d, err = b.NextDelivery("claude")
	if err != nil || d == nil || len(d.Messages) != 1 || d.Messages[0].Body != "must survive" {
		t.Fatalf("unsettled receipt was pruned: delivery=%+v err=%v", d, err)
	}
}

func TestPruneRetainsOldMessageUntilReceiptHasBeenSettledForRetentionWindow(t *testing.T) {
	b := open(t)
	if _, err := b.NextDelivery("claude"); err != nil {
		t.Fatal(err)
	}
	m, err := b.Send("codex", "claude", SendOpts{
		Body: "sat unprocessed for months", ClientMessageID: "recently-settled-old-message",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`UPDATE messages SET ts = ? WHERE seq = ?`, time.Now().Add(-60*24*time.Hour).UTC().Format(time.RFC3339Nano), m.Seq); err != nil {
		t.Fatal(err)
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}

	pruned, err := b.Prune(time.Now().Add(-30 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if pruned.Messages != 0 || pruned.Receipts != 0 {
		t.Fatalf("recently settled receipt must retain its old payload, got %+v", pruned)
	}
}

func TestPruneRetainsBroadcastUntilEveryReceiptPassesRetentionWindow(t *testing.T) {
	b := open(t)
	for _, name := range []string{"claude", "athena"} {
		if _, err := b.NextDelivery(name); err != nil {
			t.Fatal(err)
		}
	}
	m, err := b.Send("codex", "*", SendOpts{
		Body: "shared payload", ClientMessageID: "staggered-broadcast-prune",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"claude", "athena"} {
		d, err := b.NextDelivery(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Ack(name, d.ID); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-60 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := b.db.Exec(
		`UPDATE receipts SET settled_at = ? WHERE mailbox_name = 'claude' AND message_seq = ?`, old, m.Seq); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	if result, err := b.Prune(cutoff); err != nil {
		t.Fatal(err)
	} else if result.Messages != 0 || result.Receipts != 0 {
		t.Fatalf("one recently settled broadcast receipt must retain all shared state, got %+v", result)
	}
	if _, err := b.db.Exec(
		`UPDATE receipts SET settled_at = ? WHERE mailbox_name = 'athena' AND message_seq = ?`, old, m.Seq); err != nil {
		t.Fatal(err)
	}
	if result, err := b.Prune(cutoff); err != nil {
		t.Fatal(err)
	} else if result.Messages != 1 || result.Receipts != 2 {
		t.Fatalf("broadcast must prune after every receipt ages out, got %+v", result)
	}
}

func TestPruneUsesFixedWidthMillisecondCutoffAtBoundary(t *testing.T) {
	b := open(t)
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "millisecond boundary", ClientMessageID: "prune-millisecond-boundary", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}
	settled := "2026-01-02T03:04:05.100Z"
	if _, err := b.db.Exec(`UPDATE receipts SET settled_at = ? WHERE mailbox_name = 'claude'`, settled); err != nil {
		t.Fatal(err)
	}
	equalCutoff := time.Date(2026, 1, 2, 3, 4, 5, 100_000_000, time.UTC)
	if result, err := b.Prune(equalCutoff); err != nil {
		t.Fatal(err)
	} else if result.Messages != 0 || result.Receipts != 0 {
		t.Fatalf("receipt settled exactly at cutoff must not be pruned, got %+v", result)
	}
	if result, err := b.Prune(equalCutoff.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	} else if result.Messages != 1 || result.Receipts != 1 {
		t.Fatalf("receipt older than next millisecond cutoff must prune, got %+v", result)
	}
}

func TestSendIdempotencySurvivesPayloadPruning(t *testing.T) {
	b := open(t)

	first, err := b.Send("codex", "claude", SendOpts{
		Body: "prunable payload", Data: json.RawMessage(`{"result":42}`),
		ClientMessageID: "durable-dedup", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Prune(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	retry, err := b.Send("codex", "claude", SendOpts{
		Body: "prunable payload", Data: json.RawMessage(`{"result":42}`),
		ClientMessageID: "durable-dedup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if retry.MessageID != first.MessageID || retry.Seq != first.Seq || retry.TS != first.TS {
		t.Fatalf("pruned send retry must return its original receipt: first=%+v retry=%+v", first, retry)
	}
	if d, err := b.NextDelivery("claude"); err != nil || d != nil {
		t.Fatalf("pruned send retry created a new delivery: %+v %v", d, err)
	}
}

func TestDeadLetterAuditSurvivesPayloadPruning(t *testing.T) {
	b := open(t)

	poison, err := b.Send("codex", "claude", SendOpts{
		Body: "poison", ClientMessageID: "audit-poison", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Skip("claude", poison.MessageID, "invalid tool request"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Prune(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	dls, err := b.DeadLetters("claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(dls) != 1 || dls[0].MessageID != poison.MessageID || dls[0].Reason != "invalid tool request" {
		t.Fatalf("dead-letter audit disappeared after prune: %+v", dls)
	}
}

func TestMintRekeyAndPruneWriteDurableSecretFreeAuditEvents(t *testing.T) {
	b := open(t)
	firstToken, err := b.Mint("claude")
	if err != nil {
		t.Fatal(err)
	}
	secondToken, err := b.Mint("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("claude", "codex", SendOpts{
		Body: "prunable", ClientMessageID: "audited-prune", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	d, err := b.NextDelivery("codex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("codex", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Prune(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	events, err := b.AuditEvents(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Action != "mint" || events[1].Action != "rekey" || events[2].Action != "prune" {
		t.Fatalf("want durable mint/rekey/prune audit sequence, got %+v", events)
	}
	if !strings.Contains(events[2].Reason, "messages=1 receipts=1") {
		t.Fatalf("prune audit must include aggregate result counts, got %q", events[2].Reason)
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), firstToken) || strings.Contains(string(encoded), secondToken) {
		t.Fatal("credential secret leaked into audit event")
	}
	if _, err := b.Prune(time.Now().Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	events, err = b.AuditEvents(0, 100)
	if err != nil || len(events) != 4 {
		t.Fatalf("audit events must survive later pruning: events=%+v err=%v", events, err)
	}
}

func TestAuditEventsAreBoundedAndPaginated(t *testing.T) {
	b := open(t)
	for _, name := range []string{"amara", "athena", "solane"} {
		if _, err := b.Mint(name); err != nil {
			t.Fatal(err)
		}
	}

	first, err := b.AuditEvents(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].ID >= first[1].ID {
		t.Fatalf("first page = %+v", first)
	}
	second, err := b.AuditEvents(first[1].ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].ID <= first[1].ID {
		t.Fatalf("second page = %+v", second)
	}
	for _, tc := range []struct {
		after int64
		limit int
	}{
		{after: -1, limit: 1},
		{after: 0, limit: 0},
		{after: 0, limit: 1001},
	} {
		if _, err := b.AuditEvents(tc.after, tc.limit); !errors.Is(err, ErrInvalidPagination) {
			t.Fatalf("AuditEvents(%d, %d) error = %v", tc.after, tc.limit, err)
		}
	}
}

func TestAuditReasonsAreBounded(t *testing.T) {
	b := open(t)
	m, err := b.Send("codex", "claude", SendOpts{
		Body: "poison", ClientMessageID: "bounded-audit-reason", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tooLong := strings.Repeat("x", maxAuditReasonBytes+1)
	if err := b.Skip("claude", m.MessageID, tooLong); !errors.Is(err, ErrInvalidReason) {
		t.Fatalf("skip error = %v", err)
	}
	if err := b.Retire("claude", tooLong); !errors.Is(err, ErrInvalidReason) {
		t.Fatalf("retire error = %v", err)
	}
}

func TestBacklogReportsActiveAndReservedUnsettledObligations(t *testing.T) {
	b := open(t)
	if _, err := b.NextDelivery("claude"); err != nil {
		t.Fatal(err)
	}
	claudeOpts := []SendOpts{
		{Body: "one", ClientMessageID: "backlog-claude-1"},
		{Body: "two", ClientMessageID: "backlog-claude-2"},
	}
	for _, opts := range claudeOpts {
		if _, err := b.Send("codex", "claude", opts); err != nil {
			t.Fatal(err)
		}
	}
	futureOpts := SendOpts{Body: "reserved", ClientMessageID: "backlog-reserved", AllowNew: true}
	if _, err := b.Send("codex", "future", futureOpts); err != nil {
		t.Fatal(err)
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.NextDelivery("claude"); err != nil { // second offer increments attempts
		t.Fatal(err)
	}

	report, err := b.Backlog()
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := int64(encodedMessageBytes("codex", "claude", claudeOpts[0]) +
		encodedMessageBytes("codex", "claude", claudeOpts[1]) +
		encodedMessageBytes("codex", "future", futureOpts))
	if report.TotalReceipts != 3 || report.TotalBytes != wantBytes {
		t.Fatalf("wrong global backlog totals: %+v", report)
	}
	entries := make(map[string]BacklogMailbox)
	for _, entry := range report.Mailboxes {
		entries[entry.Name] = entry
	}
	if got := entries["claude"]; got.State != "active" || got.Receipts != 2 || got.MaxAttempts != 2 {
		t.Fatalf("wrong active mailbox backlog: %+v", got)
	}
	if got := entries["future"]; got.State != "reserved" || got.Receipts != 1 || got.MaxAttempts != 0 {
		t.Fatalf("wrong reserved mailbox backlog: %+v", got)
	}
	if _, ok := entries["codex"]; !ok {
		t.Fatal("active mailbox with zero backlog must remain inspectable")
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}
	report, err = b.Backlog()
	if err != nil || report.TotalReceipts != 1 || report.TotalBytes != int64(encodedMessageBytes("codex", "future", futureOpts)) {
		t.Fatalf("settled receipts remained in backlog: report=%+v err=%v", report, err)
	}
}

func TestActivityReportsDurableBodyFreeUsageAfterPruning(t *testing.T) {
	b := open(t)
	for _, name := range []string{"athena", "solane"} {
		if d, err := b.NextDelivery(name); err != nil || d != nil {
			t.Fatalf("activate %s: delivery=%v err=%v", name, d, err)
		}
	}

	ackOpts := SendOpts{
		Body: "ACTIVITY_SECRET_BODY_MUST_NOT_APPEAR", ClientMessageID: "activity-ack",
	}
	if _, err := b.Send("amara", "athena", ackOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("amara", "athena", ackOpts); err != nil { // idempotent retry is not new activity
		t.Fatal(err)
	}
	d, err := b.NextDelivery("athena")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.NextDelivery("athena"); err != nil { // one redelivery offer
		t.Fatal(err)
	}
	if _, err := b.Ack("athena", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("athena", d.ID); err != nil { // idempotent ack is not new activity
		t.Fatal(err)
	}

	dead, err := b.Send("amara", "solane", SendOpts{
		Body: "poison", ClientMessageID: "activity-dead",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Skip("solane", dead.MessageID, "activity test"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Prune(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	report, err := b.Activity()
	if err != nil {
		t.Fatal(err)
	}
	if report.AsOf == "" || report.TrackingStartedAt == "" ||
		report.SinceTracking.MessagesSent != 2 || report.SinceTracking.ReceiptsEnqueued != 2 ||
		report.SinceTracking.ReceiptsAcked != 1 || report.SinceTracking.ReceiptsDead != 1 ||
		report.SinceTracking.OfferAttempts != 2 || report.Current.PendingReceipts != 0 ||
		report.Current.OfferedReceipts != 0 || report.Current.OutstandingDeliveries != 0 {
		t.Fatalf("wrong global activity after pruning: %+v", report)
	}
	entries := make(map[string]ActivityMailbox)
	for _, entry := range report.Mailboxes {
		entries[entry.Name] = entry
	}
	if got := entries["amara"]; got.State != "active" || got.SinceTracking.MessagesSent != 2 || got.LastSentAt == "" {
		t.Fatalf("wrong sender activity: %+v", got)
	}
	if got := entries["athena"]; got.SinceTracking.ReceiptsEnqueued != 1 || got.SinceTracking.ReceiptsAcked != 1 ||
		got.SinceTracking.OfferAttempts != 2 || got.LastEnqueuedAt == "" || got.LastOfferedAt == "" || got.LastAckedAt == "" {
		t.Fatalf("wrong acknowledged activity: %+v", got)
	}
	if got := entries["solane"]; got.SinceTracking.ReceiptsEnqueued != 1 || got.SinceTracking.ReceiptsDead != 1 || got.SinceTracking.OfferAttempts != 0 || got.LastDeadAt == "" {
		t.Fatalf("wrong dead-letter activity: %+v", got)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("ACTIVITY_SECRET_BODY_MUST_NOT_APPEAR")) {
		t.Fatal("activity report leaked a message body")
	}
}

func TestRecentRoutesReturnsBodyFreeNewestPage(t *testing.T) {
	b := open(t)
	for i := 1; i <= 3; i++ {
		if _, err := b.Send("amara", "athena", SendOpts{
			Body:            fmt.Sprintf("ROUTE_SECRET_BODY_%d", i),
			Data:            json.RawMessage(fmt.Sprintf(`{"secret":"ROUTE_SECRET_DATA_%d"}`, i)),
			ClientMessageID: fmt.Sprintf("route-secret-client-id-%d", i),
			AllowNew:        true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	routes, err := b.RecentRoutes(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].Seq != 3 || routes[1].Seq != 2 ||
		routes[0].From != "amara" || routes[0].To != "athena" {
		t.Fatalf("recent routes are not the newest deterministic page: %+v", routes)
	}
	raw, err := json.Marshal(routes)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"ROUTE_SECRET_BODY", "ROUTE_SECRET_DATA", "route-secret-client-id"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("recent route metadata exposed %q: %s", secret, raw)
		}
	}
}

func TestRecentRoutesSummarizesReceiptStates(t *testing.T) {
	b := open(t)
	for _, name := range []string{"athena", "solane"} {
		if delivery, err := b.NextDelivery(name); err != nil || delivery != nil {
			t.Fatalf("activate %s: delivery=%v err=%v", name, delivery, err)
		}
	}
	if _, err := b.Send("amara", "*", SendOpts{
		Body: "fanout", ClientMessageID: "route-receipt-states",
	}); err != nil {
		t.Fatal(err)
	}
	delivery, err := b.NextDelivery("athena")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("athena", delivery.ID); err != nil {
		t.Fatal(err)
	}

	routes, err := b.RecentRoutes(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Receipts.Pending != 1 || routes[0].Receipts.Acked != 1 ||
		routes[0].Receipts.Offered != 0 || routes[0].Receipts.Dead != 0 {
		t.Fatalf("wrong receipt summary: %+v", routes)
	}
}

func TestMessageContentReturnsOneRetainedMessage(t *testing.T) {
	b := open(t)
	replyTo := "msg_00000000000000000000000000000001"
	sent, err := b.Send("amara", "athena", SendOpts{
		Body:            `<script>alert("stored xss")</script></pre>`,
		Data:            json.RawMessage(`{"html":"<img src=x onerror=alert(1)>"}`),
		ReplyTo:         &replyTo,
		ClientMessageID: "content-inspection",
		AllowNew:        true,
	})
	if err != nil {
		t.Fatal(err)
	}

	content, err := b.MessageContent(sent.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	if content.MessageID != sent.MessageID || content.Body != sent.Body ||
		string(content.Data) != string(sent.Data) || content.ReplyTo == nil || *content.ReplyTo != replyTo {
		t.Fatalf("wrong retained message content: %+v", content)
	}
}

func TestRecentRoutesPaginationIsStableWhileNewMessagesArrive(t *testing.T) {
	b := open(t)
	for i := 1; i <= 4; i++ {
		if _, err := b.Send("amara", "athena", SendOpts{
			Body: "work", ClientMessageID: fmt.Sprintf("stable-route-%d", i), AllowNew: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := b.RecentRoutes(0, 2)
	if err != nil || len(first) != 2 || first[0].Seq != 4 || first[1].Seq != 3 {
		t.Fatalf("first page = %+v err=%v", first, err)
	}
	if _, err := b.Send("amara", "athena", SendOpts{
		Body: "new arrival", ClientMessageID: "stable-route-new",
	}); err != nil {
		t.Fatal(err)
	}
	second, err := b.RecentRoutes(first[1].Seq, 2)
	if err != nil || len(second) != 2 || second[0].Seq != 2 || second[1].Seq != 1 {
		t.Fatalf("stable second page = %+v err=%v", second, err)
	}
	for _, request := range []struct {
		before int64
		limit  int
	}{{-1, 1}, {0, 0}, {0, maxRecentRoutes + 1}} {
		if _, err := b.RecentRoutes(request.before, request.limit); !errors.Is(err, ErrInvalidPagination) {
			t.Fatalf("RecentRoutes(%d, %d) error = %v", request.before, request.limit, err)
		}
	}
}

func TestMessageContentDisappearsOnlyAfterTerminalPruning(t *testing.T) {
	b := open(t)
	if delivery, err := b.NextDelivery("athena"); err != nil || delivery != nil {
		t.Fatal(delivery, err)
	}
	sent, err := b.Send("amara", "athena", SendOpts{
		Body: "terminal", ClientMessageID: "content-pruning",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := b.NextDelivery("athena")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("athena", delivery.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Prune(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.MessageContent(sent.MessageID); !errors.Is(err, ErrMessageNotFound) {
		t.Fatalf("pruned MessageContent error = %v", err)
	}
}

func TestActivityCountsBroadcastUnitsAndCurrentGauges(t *testing.T) {
	b := open(t)
	if d, err := b.NextDelivery("amara"); err != nil || d != nil {
		t.Fatal(d, err)
	}
	if _, err := b.Send("amara", "*", SendOpts{
		Body: "no recipients", ClientMessageID: "activity-empty-broadcast",
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"athena", "solane"} {
		if d, err := b.NextDelivery(name); err != nil || d != nil {
			t.Fatal(d, err)
		}
	}
	if _, err := b.Send("amara", "*", SendOpts{
		Body: "fanout", ClientMessageID: "activity-fanout",
	}); err != nil {
		t.Fatal(err)
	}

	report, err := b.Activity()
	if err != nil {
		t.Fatal(err)
	}
	if report.SinceTracking.MessagesSent != 2 || report.SinceTracking.ReceiptsEnqueued != 2 ||
		report.Current.PendingReceipts != 2 || report.Current.OfferedReceipts != 0 {
		t.Fatalf("broadcast activity units are wrong: %+v", report)
	}
	entries := make(map[string]ActivityMailbox)
	for _, entry := range report.Mailboxes {
		entries[entry.Name] = entry
	}
	if got := entries["amara"]; got.SinceTracking.MessagesSent != 2 || got.SinceTracking.ReceiptsEnqueued != 0 {
		t.Fatalf("sender broadcast activity is wrong: %+v", got)
	}
	for _, name := range []string{"athena", "solane"} {
		got := entries[name]
		if got.SinceTracking.ReceiptsEnqueued != 1 || got.Current.PendingReceipts != 1 {
			t.Fatalf("recipient %s broadcast activity is wrong: %+v", name, got)
		}
	}
}

func TestActivityCountsReceiptTransitionsOnce(t *testing.T) {
	b := open(t)
	if d, err := b.NextDelivery("athena"); err != nil || d != nil {
		t.Fatal(d, err)
	}
	var messages []Message
	for i := 0; i < 2; i++ {
		m, err := b.Send("amara", "athena", SendOpts{
			Body: "work", ClientMessageID: fmt.Sprintf("activity-transition-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		messages = append(messages, m)
	}
	if _, err := b.NextDelivery("athena"); err != nil {
		t.Fatal(err)
	}
	if err := b.Skip("athena", messages[0].MessageID, "poison"); err != nil {
		t.Fatal(err)
	}
	if err := b.Retire("athena", "decommissioned"); err != nil {
		t.Fatal(err)
	}
	if err := b.Retire("athena", "idempotent retry"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("amara", "ghost", SendOpts{
		Body: "rejected", ClientMessageID: "activity-rejected",
	}); !errors.Is(err, ErrUnknownRecipient) {
		t.Fatalf("rejected send error = %v", err)
	}

	report, err := b.Activity()
	if err != nil {
		t.Fatal(err)
	}
	if report.SinceTracking.MessagesSent != 2 || report.SinceTracking.ReceiptsEnqueued != 2 ||
		report.SinceTracking.OfferAttempts != 2 || report.SinceTracking.ReceiptsDead != 2 ||
		report.Current.PendingReceipts != 0 || report.Current.OfferedReceipts != 0 ||
		report.Current.OutstandingDeliveries != 0 {
		t.Fatalf("receipt transition counters drifted: %+v", report)
	}
}

func TestActivityMailboxOutputIsBounded(t *testing.T) {
	b := open(t)
	for i := 0; i <= maxActivityMailboxes; i++ {
		name := fmt.Sprintf("mailbox-%03d", i)
		if d, err := b.NextDelivery(name); err != nil || d != nil {
			t.Fatalf("activate %s: delivery=%v err=%v", name, d, err)
		}
	}
	report, err := b.Activity()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Truncated || len(report.Mailboxes) != maxActivityMailboxes {
		t.Fatalf("activity output is not bounded: truncated=%v mailboxes=%d", report.Truncated, len(report.Mailboxes))
	}
	if report.Mailboxes[0].Name != "mailbox-000" || report.Mailboxes[len(report.Mailboxes)-1].Name != "mailbox-255" {
		t.Fatalf("activity truncation must be deterministic: first=%s last=%s",
			report.Mailboxes[0].Name, report.Mailboxes[len(report.Mailboxes)-1].Name)
	}
}

func TestActivityDoesNotInventPreTrackingHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:2] {
		if _, err := db.Exec(m.sql); err != nil {
			t.Fatal(err)
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256([]byte(m.sql)))
		if _, err := db.Exec(
			`INSERT INTO schema_migrations(version, checksum) VALUES(?, ?)`, m.version, checksum); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`
		INSERT INTO mailboxes(name, state, last_seen) VALUES
			('amara', 'active', '2026-01-01T00:00:00.000Z'),
			('athena', 'active', '2026-01-01T00:00:00.000Z');
		INSERT INTO messages(
			message_id, from_name, to_name, body, encoded_bytes, client_message_id
		) VALUES('msg_00000000000000000000000000000001', 'amara', 'athena', 'old', 3, 'old-send');
		INSERT INTO receipts(mailbox_name, message_seq, state)
		SELECT 'athena', seq, 'pending' FROM messages;`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	report, err := b.Activity()
	if err != nil {
		t.Fatal(err)
	}
	if report.SinceTracking != (ActivityCounters{}) || report.Current.PendingReceipts != 1 {
		t.Fatalf("migration invented historical activity: %+v", report)
	}
	d, err := b.NextDelivery("athena")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("athena", d.ID); err != nil {
		t.Fatal(err)
	}
	report, err = b.Activity()
	if err != nil {
		t.Fatal(err)
	}
	if report.SinceTracking.MessagesSent != 0 || report.SinceTracking.ReceiptsEnqueued != 0 ||
		report.SinceTracking.OfferAttempts != 1 || report.SinceTracking.ReceiptsAcked != 1 {
		t.Fatalf("post-tracking transitions were misattributed: %+v", report)
	}
}

// Slice 6: batches are capped and contiguous; the next delivery after ack
// paginates through the remainder; oversize messages are rejected at send.
func TestBatchCapsAndPagination(t *testing.T) {
	b := open(t)

	if d, err := b.NextDelivery("claude"); err != nil || d != nil { // claude self-creates
		t.Fatal(d, err)
	}
	for i := 0; i < 120; i++ {
		if _, err := b.Send("codex", "claude", SendOpts{Body: "m", ClientMessageID: fmt.Sprintf("page-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}

	d1, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(d1.Messages) != 100 {
		t.Fatalf("batch must cap at 100 messages, got %d", len(d1.Messages))
	}
	if d1.Through != d1.Messages[99].Seq {
		t.Errorf("through must be the last delivered seq")
	}
	if _, err := b.Ack("claude", d1.ID); err != nil {
		t.Fatal(err)
	}

	d2, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(d2.Messages) != 20 {
		t.Fatalf("pagination must deliver the remaining 20, got %d", len(d2.Messages))
	}
	if d2.Messages[0].Seq != d1.Through+1 {
		t.Errorf("pagination must be gapless: got seq %d after through %d", d2.Messages[0].Seq, d1.Through)
	}

	big := make([]byte, 65*1024)
	for i := range big {
		big[i] = 'x'
	}
	if _, err := b.Send("codex", "claude", SendOpts{Body: string(big), ClientMessageID: "oversize"}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversize message must be rejected, got %v", err)
	}
}

func TestBatchCapIncludesDeliveryEnvelope(t *testing.T) {
	b := open(t)
	if _, err := b.NextDelivery("claude"); err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", 63*1024)
	for i := 0; i < 6; i++ {
		if _, err := b.Send("codex", "claude", SendOpts{
			Body: body, ClientMessageID: fmt.Sprintf("envelope-cap-%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	// MCP adds a small mail/delivery wrapper around the bus delivery. The
	// batcher reserves that complete envelope, not just the messages array.
	wire := struct {
		Mail     bool      `json:"mail"`
		Delivery *Delivery `json:"delivery"`
	}{Mail: true, Delivery: d}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > maxBatchBytes {
		t.Fatalf("encoded delivery = %d bytes, cap = %d", len(encoded), maxBatchBytes)
	}
	if len(d.Messages) >= 6 {
		t.Fatalf("test did not force byte pagination: %d messages", len(d.Messages))
	}
}

func TestMessageSizeLimitAccountsForFullWireEnvelope(t *testing.T) {
	b := open(t)
	worstCase := Message{
		Seq:       9_223_372_036_854_775_807,
		MessageID: "msg_ffffffffffffffffffffffffffffffff",
		From:      "codex",
		To:        "claude",
		TS:        "9999-12-31T23:59:59.999Z",
	}
	emptyWire, err := json.Marshal(worstCase)
	if err != nil {
		t.Fatal(err)
	}
	fitBody := strings.Repeat("x", maxMessageBytes-len(emptyWire))
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: fitBody, ClientMessageID: "full-wire-fits", AllowNew: true,
	}); err != nil {
		t.Fatalf("message whose full wire encoding fits exactly must succeed: %v", err)
	}
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: fitBody + "x", ClientMessageID: "full-wire-overflow",
	}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("message whose payload fits but full wire envelope does not must be rejected, got %v", err)
	}
}

// Slice 5: parking. Queued mail returns immediately; an empty inbox parks
// until send (including broadcast) or context expiry. The register-before-
// check loop is exercised by racing send against wait repeatedly — a lost
// wakeup hangs a round and fails the guard timeout.
func TestWaitDeliveryParksAndWakes(t *testing.T) {
	b := open(t)

	// Queued mail: returns immediately, no parking.
	if _, err := b.Send("codex", "claude", SendOpts{Body: "queued", ClientMessageID: "wait-queued", AllowNew: true}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	d, err := b.WaitDelivery(ctx, "claude")
	cancel()
	if err != nil || d == nil || d.Messages[0].Body != "queued" {
		t.Fatalf("queued mail must return without parking: %+v, %v", d, err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}

	// Empty inbox + context expiry: parks, then returns nil.
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	d, err = b.WaitDelivery(ctx, "claude")
	cancel()
	if err != nil || d != nil {
		t.Fatalf("timeout on empty inbox must return nil delivery: %+v, %v", d, err)
	}

	// Race send against wait; a lost wakeup makes a round hang past the guard.
	for i := 0; i < 25; i++ {
		got := make(chan *Delivery, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		go func() {
			d, err := b.WaitDelivery(ctx, "claude")
			if err != nil {
				t.Error(err)
			}
			got <- d
		}()
		to := "claude"
		if i%2 == 1 {
			to = "*" // broadcasts must wake parked waiters too
		}
		if _, err := b.Send("codex", to, SendOpts{Body: "wake", ClientMessageID: fmt.Sprintf("wake-%d", i)}); err != nil {
			t.Fatal(err)
		}
		select {
		case d := <-got:
			if d == nil {
				t.Fatalf("round %d: waiter timed out despite mail (lost wakeup)", i)
			}
			if _, err := b.Ack("claude", d.ID); err != nil {
				t.Fatal(err)
			}
		case <-time.After(4 * time.Second):
			t.Fatalf("round %d: waiter hung (lost wakeup)", i)
		}
		cancel()
	}
}

func TestWaitDeliveryRejectsSecondParkedWaiterForOneConsumerIdentity(t *testing.T) {
	b := open(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 1)
	go func() {
		_, err := b.WaitDelivery(ctx, "claude")
		results <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		parked := len(b.waiters["claude"])
		b.mu.Unlock()
		if parked == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiters did not park; got %d", parked)
		}
		time.Sleep(time.Millisecond)
	}

	if _, err := b.WaitDelivery(context.Background(), "claude"); !errors.Is(err, ErrWaiterLimit) {
		t.Fatalf("second parked waiter for one-consumer identity must be rejected, got %v", err)
	}
	cancel()
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

func TestWaitDeliveryBoundsGlobalWaiters(t *testing.T) {
	b := open(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, maxWaiters)
	for i := range maxWaiters {
		name := fmt.Sprintf("worker-%d", i)
		go func() {
			_, err := b.WaitDelivery(ctx, name)
			results <- err
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		b.mu.Lock()
		parked := b.waiterCount
		b.mu.Unlock()
		if parked == maxWaiters {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiters did not park; got %d", parked)
		}
		time.Sleep(time.Millisecond)
	}

	if _, err := b.WaitDelivery(context.Background(), "overflow"); !errors.Is(err, ErrWaiterLimit) {
		t.Fatalf("waiter above global limit must be rejected, got %v", err)
	}
	cancel()
	for range maxWaiters {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestIdempotentSendRetryDoesNotWakeParkedMailbox(t *testing.T) {
	b := open(t)
	if _, err := b.NextDelivery("claude"); err != nil {
		t.Fatal(err)
	}
	opts := SendOpts{Body: "once", ClientMessageID: "no-false-wake"}
	if _, err := b.Send("codex", "claude", opts); err != nil {
		t.Fatal(err)
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = b.WaitDelivery(ctx, "claude")
	}()
	var parked chan struct{}
	deadline := time.Now().Add(time.Second)
	for parked == nil {
		b.mu.Lock()
		if len(b.waiters["claude"]) == 1 {
			parked = b.waiters["claude"][0]
		}
		b.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("waiter did not park")
		}
		time.Sleep(time.Millisecond)
	}

	if _, err := b.Send("codex", "claude", opts); err != nil {
		t.Fatal(err)
	}
	select {
	case <-parked:
		t.Fatal("deduplicated send retry woke a mailbox without creating mail")
	default:
	}
	cancel()
	<-done
}

// Slice 4: broadcasts are future-only relative to first_seen_seq; old direct
// mail still delivers; unknown direct recipients are rejected without
// AllowNew; sending never creates the recipient identity; own broadcasts are
// not delivered back; names are validated.
func TestBroadcastFirstSeenAndUnknownRecipients(t *testing.T) {
	b := open(t)

	if _, err := b.Send("codex", "*", SendOpts{Body: "old broadcast", ClientMessageID: "broadcast-old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "claude", SendOpts{Body: "old dm", ClientMessageID: "dm-rejected"}); !errors.Is(err, ErrUnknownRecipient) {
		t.Fatalf("unknown direct recipient must be rejected, got %v", err)
	}
	oldDM, err := b.Send("codex", "claude", SendOpts{Body: "old dm", ClientMessageID: "dm-allowed", AllowNew: true})
	if err != nil {
		t.Fatalf("AllowNew must override, got %v", err)
	}

	d, err := b.NextDelivery("claude") // claude's first acting call
	if err != nil {
		t.Fatal(err)
	}
	if d == nil || len(d.Messages) != 1 || d.Messages[0].Seq != oldDM.Seq {
		t.Fatalf("want only the old DM (broadcasts are future-only), got %+v", d)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := b.Send("codex", "*", SendOpts{Body: "new broadcast", ClientMessageID: "broadcast-new"}); err != nil {
		t.Fatal(err)
	}
	d2, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if d2 == nil || len(d2.Messages) != 1 || d2.Messages[0].Body != "new broadcast" {
		t.Fatalf("broadcast after first_seen must deliver, got %+v", d2)
	}

	if dcx, err := b.NextDelivery("codex"); err != nil || dcx != nil {
		t.Fatalf("sender must not receive its own messages, got %+v, %v", dcx, err)
	}

	if _, err := b.Send("codex", "no such agent!", SendOpts{Body: "x", ClientMessageID: "bad-recipient", AllowNew: true}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("invalid recipient name must be rejected, got %v", err)
	}
	if _, err := b.Send("BAD NAME", "codex", SendOpts{Body: "x", ClientMessageID: "bad-sender"}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("invalid sender name must be rejected, got %v", err)
	}
}

func TestAllowNewReservesMailboxWithoutJoiningBroadcasts(t *testing.T) {
	b := open(t)

	if _, err := b.Send("codex", "future", SendOpts{
		Body: "first contact", ClientMessageID: "reserve-first", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "future", SendOpts{
		Body: "follow-up", ClientMessageID: "reserve-second",
	}); err != nil {
		t.Fatalf("reserved mailbox must be a known direct address: %v", err)
	}
	if _, err := b.Send("codex", "*", SendOpts{
		Body: "active mailboxes only", ClientMessageID: "reserve-broadcast",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Retire("future", "never activated"); err != nil {
		t.Fatalf("reserved mailbox must be retireable: %v", err)
	}
	dls, err := b.DeadLetters("future")
	if err != nil {
		t.Fatal(err)
	}
	if len(dls) != 2 {
		t.Fatalf("retirement must dead-letter only the two direct receipts, got %+v", dls)
	}
}

func TestAllowNewRejectsReservedMailboxBacklogPastHardCap(t *testing.T) {
	b := open(t)

	for i := range maxReservedMailboxes {
		if _, err := b.Send("codex", fmt.Sprintf("reserved-%d", i), SendOpts{
			Body:            "first contact",
			ClientMessageID: fmt.Sprintf("reserve-cap-%d", i),
			AllowNew:        true,
		}); err != nil {
			t.Fatalf("reserve mailbox %d: %v", i, err)
		}
	}
	overflow := SendOpts{
		Body: "must be rejected", ClientMessageID: "reserve-cap-overflow", AllowNew: true,
	}
	if _, err := b.Send("codex", "reserved-overflow", overflow); !errors.Is(err, ErrBacklogLimit) {
		t.Fatalf("reserved mailbox above hard cap must fail with backlog limit, got %v", err)
	}

	// The rejected transaction must not leave a phantom mailbox or dedup row.
	overflow.AllowNew = false
	if _, err := b.Send("codex", "reserved-overflow", overflow); !errors.Is(err, ErrUnknownRecipient) {
		t.Fatalf("rejected reservation mutated durable state, got %v", err)
	}
}

func TestDirectSendRejectsMailboxReceiptBacklogPastHardCap(t *testing.T) {
	b := open(t)
	b.backlogLimits.mailboxReceipts = 2

	for i := range 2 {
		if _, err := b.Send("codex", "claude", SendOpts{
			Body:            fmt.Sprintf("queued-%d", i),
			ClientMessageID: fmt.Sprintf("mailbox-count-%d", i),
			AllowNew:        i == 0,
		}); err != nil {
			t.Fatal(err)
		}
	}
	overflow := SendOpts{Body: "after capacity", ClientMessageID: "mailbox-count-overflow"}
	if _, err := b.Send("codex", "claude", overflow); !errors.Is(err, ErrBacklogLimit) {
		t.Fatalf("mailbox above unsettled receipt cap must reject direct mail, got %v", err)
	}

	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "claude", overflow); err != nil {
		t.Fatalf("settling receipts must release capacity and rejected send must remain retryable: %v", err)
	}
	d, err = b.NextDelivery("claude")
	if err != nil || d == nil || len(d.Messages) != 1 || d.Messages[0].Body != overflow.Body {
		t.Fatalf("retried send was not durably enqueued: delivery=%+v err=%v", d, err)
	}
}

func TestDirectSendRejectsMailboxByteBacklogPastHardCap(t *testing.T) {
	b := open(t)
	first := SendOpts{
		Body: strings.Repeat("x", 128), ClientMessageID: "mailbox-bytes-first", AllowNew: true,
	}
	b.backlogLimits.mailboxBytes = int64(encodedMessageBytes("codex", "claude", first))
	if _, err := b.Send("codex", "claude", first); err != nil {
		t.Fatal(err)
	}
	overflow := SendOpts{Body: "one byte too many", ClientMessageID: "mailbox-bytes-overflow"}
	if _, err := b.Send("codex", "claude", overflow); !errors.Is(err, ErrBacklogLimit) {
		t.Fatalf("mailbox above unsettled byte cap must reject direct mail, got %v", err)
	}

	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "claude", overflow); err != nil {
		t.Fatalf("settling payload bytes must release mailbox capacity: %v", err)
	}
}

func TestDirectSendRejectsGlobalReceiptBacklogPastHardCap(t *testing.T) {
	b := open(t)
	b.backlogLimits.globalReceipts = 1
	for _, name := range []string{"claude", "athena"} {
		if _, err := b.NextDelivery(name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "occupies global slot", ClientMessageID: "global-count-first",
	}); err != nil {
		t.Fatal(err)
	}
	overflow := SendOpts{Body: "after capacity", ClientMessageID: "global-count-overflow"}
	if _, err := b.Send("codex", "athena", overflow); !errors.Is(err, ErrBacklogLimit) {
		t.Fatalf("global unsettled receipt cap must reject direct mail, got %v", err)
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "athena", overflow); err != nil {
		t.Fatalf("settling a receipt must release global capacity: %v", err)
	}
}

func TestDirectSendRejectsGlobalByteBacklogPastHardCap(t *testing.T) {
	b := open(t)
	for _, name := range []string{"claude", "athena"} {
		if _, err := b.NextDelivery(name); err != nil {
			t.Fatal(err)
		}
	}
	first := SendOpts{Body: strings.Repeat("x", 128), ClientMessageID: "global-bytes-first"}
	b.backlogLimits.globalBytes = int64(encodedMessageBytes("codex", "claude", first))
	if _, err := b.Send("codex", "claude", first); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "athena", SendOpts{
		Body: "after capacity", ClientMessageID: "global-bytes-overflow",
	}); !errors.Is(err, ErrBacklogLimit) {
		t.Fatalf("global unsettled byte cap must reject direct mail, got %v", err)
	}
}

func TestBroadcastRejectsAtomicallyWhenAnyMailboxIsAtBacklogCap(t *testing.T) {
	b := open(t)
	b.backlogLimits.mailboxReceipts = 1
	for _, name := range []string{"claude", "athena"} {
		if _, err := b.NextDelivery(name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "fills claude", ClientMessageID: "broadcast-cap-direct",
	}); err != nil {
		t.Fatal(err)
	}
	broadcast := SendOpts{Body: "all or nobody", ClientMessageID: "broadcast-cap-overflow"}
	if _, err := b.Send("codex", "*", broadcast); !errors.Is(err, ErrBacklogLimit) {
		t.Fatalf("broadcast with one full recipient must fail atomically, got %v", err)
	}
	if d, err := b.NextDelivery("athena"); err != nil || d != nil {
		t.Fatalf("failed broadcast silently delivered to non-full recipient: delivery=%+v err=%v", d, err)
	}

	d, err := b.NextDelivery("claude")
	if err != nil || d == nil || len(d.Messages) != 1 || d.Messages[0].Body != "fills claude" {
		t.Fatalf("full recipient's existing mail changed: delivery=%+v err=%v", d, err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "*", broadcast); err != nil {
		t.Fatalf("rejected broadcast must remain retryable after capacity is released: %v", err)
	}
	for _, name := range []string{"claude", "athena"} {
		d, err := b.NextDelivery(name)
		if err != nil || d == nil || len(d.Messages) != 1 || d.Messages[0].Body != broadcast.Body {
			t.Fatalf("%s did not receive retried broadcast exactly once: delivery=%+v err=%v", name, d, err)
		}
	}
}

func TestBroadcastCountsEveryRecipientAgainstGlobalBacklogCap(t *testing.T) {
	b := open(t)
	b.backlogLimits.globalReceipts = 1
	for _, name := range []string{"claude", "athena"} {
		if _, err := b.NextDelivery(name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Send("codex", "*", SendOpts{
		Body: "two logical obligations", ClientMessageID: "broadcast-global-cap",
	}); !errors.Is(err, ErrBacklogLimit) {
		t.Fatalf("two-recipient broadcast above global receipt cap must fail, got %v", err)
	}
	for _, name := range []string{"claude", "athena"} {
		if d, err := b.NextDelivery(name); err != nil || d != nil {
			t.Fatalf("failed broadcast partially reached %s: delivery=%+v err=%v", name, d, err)
		}
	}
}

// Slice 3: foreign and superseded ids conflict, a bad ack leaves the real one
// intact, and any retained completed delivery remains idempotently ackable.
func TestAckConflicts(t *testing.T) {
	b := open(t)

	if _, err := b.Send("codex", "claude", SendOpts{Body: "one", ClientMessageID: "ack-one", AllowNew: true}); err != nil {
		t.Fatal(err)
	}
	d1, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := b.Ack("claude", "dlv_forged"); !errors.Is(err, ErrDeliveryConflict) {
		t.Fatalf("foreign id must conflict, got %v", err)
	}
	if cur, err := b.Ack("claude", d1.ID); err != nil || cur != d1.Through {
		t.Fatalf("real delivery must still ack after a failed attempt: %d, %v", cur, err)
	}

	if _, err := b.Send("codex", "claude", SendOpts{Body: "two", ClientMessageID: "ack-two"}); err != nil {
		t.Fatal(err)
	}
	d2, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if d2.ID == d1.ID {
		t.Fatal("new batch after ack must mint a new delivery id")
	}
	if _, err := b.Ack("claude", d2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d1.ID); err != nil {
		t.Fatalf("an older completed delivery must remain idempotently ackable, got %v", err)
	}
}

// Slice 2: a retried send with the same client_message_id returns the
// original message and inserts no second row.
func TestSendIdempotency(t *testing.T) {
	b := open(t)

	replyTo := "msg_00000000000000000000000000000000"
	data := json.RawMessage(`{"status":"green"}`)
	first, err := b.Send("codex", "claude", SendOpts{
		Body: "deploy done", Data: data, ReplyTo: &replyTo,
		ClientMessageID: "cmid-1", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := b.Send("codex", "claude", SendOpts{
		Body: "deploy done", Data: data, ReplyTo: &replyTo,
		ClientMessageID: "cmid-1", AllowNew: true,
	})
	if err != nil {
		t.Fatalf("retry must succeed, got %v", err)
	}
	if retry.Seq != first.Seq || retry.MessageID != first.MessageID {
		t.Errorf("retry must return the original message: first %+v, retry %+v", first, retry)
	}
	if string(first.Data) != string(data) || first.ReplyTo == nil || *first.ReplyTo != replyTo {
		t.Fatalf("first send omitted immutable fields: %+v", first)
	}
	if string(retry.Data) != string(data) || retry.ReplyTo == nil || *retry.ReplyTo != replyTo {
		t.Fatalf("idempotent retry omitted immutable fields: %+v", retry)
	}

	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if d == nil || len(d.Messages) != 1 {
		t.Fatalf("recipient must see exactly one message, got %+v", d)
	}

	// Distinct client ids from the same sender are distinct messages.
	other, err := b.Send("codex", "claude", SendOpts{Body: "next thing", ClientMessageID: "cmid-2"})
	if err != nil {
		t.Fatal(err)
	}
	if other.Seq == first.Seq {
		t.Error("different client_message_id must create a new message")
	}
}

func TestSendRequiresClientMessageID(t *testing.T) {
	b := open(t)

	_, err := b.Send("codex", "claude", SendOpts{Body: "ambiguous retry", AllowNew: true})
	if !errors.Is(err, ErrInvalidClientMessageID) {
		t.Fatalf("send without client_message_id must fail, got %v", err)
	}
}

func TestSendRejectsMalformedReplyToMessageID(t *testing.T) {
	b := open(t)
	badReplyTo := "42"
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "not a message correlation", ReplyTo: &badReplyTo,
		ClientMessageID: "bad-reply-to", AllowNew: true,
	}); !errors.Is(err, ErrInvalidReplyTo) {
		t.Fatalf("malformed reply_to must be rejected, got %v", err)
	}
}

func TestSendRejectsConflictingIdempotencyReuse(t *testing.T) {
	b := open(t)

	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "first command", ClientMessageID: "same-key", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := b.Send("codex", "claude", SendOpts{
		Body: "different command", ClientMessageID: "same-key",
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key with different command must conflict, got %v", err)
	}
}

func TestSendCanonicalizesStructuredDataForIdempotency(t *testing.T) {
	b := open(t)

	first, err := b.Send("codex", "claude", SendOpts{
		Body: "same JSON", Data: json.RawMessage(`{"a":1,"b":2}`),
		ClientMessageID: "canonical-json", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := b.Send("codex", "claude", SendOpts{
		Body: "same JSON", Data: json.RawMessage(`{"b":2,"a":1}`),
		ClientMessageID: "canonical-json",
	})
	if err != nil {
		t.Fatalf("object key order must not change the idempotency command: %v", err)
	}
	if retry.MessageID != first.MessageID {
		t.Fatalf("canonical retry created a different message: %s != %s", retry.MessageID, first.MessageID)
	}
}

func TestConcurrentIdenticalClientMessageIDCreatesOneMessage(t *testing.T) {
	b := open(t)
	type result struct {
		message Message
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			m, err := b.Send("codex", "claude", SendOpts{
				Body: "one command", ClientMessageID: "concurrent-identical", AllowNew: true,
			})
			results <- result{message: m, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("identical concurrent retries must both succeed: %v, %v", first.err, second.err)
	}
	if first.message.MessageID != second.message.MessageID || first.message.Seq != second.message.Seq {
		t.Fatalf("identical concurrent retries created different messages: %+v, %+v", first.message, second.message)
	}
	d, err := b.NextDelivery("claude")
	if err != nil || d == nil || len(d.Messages) != 1 || d.Messages[0].MessageID != first.message.MessageID {
		t.Fatalf("recipient did not receive exactly one message: delivery=%+v err=%v", d, err)
	}
}

func TestConcurrentConflictingClientMessageIDCommitsOneCommand(t *testing.T) {
	b := open(t)
	type result struct {
		body    string
		message Message
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, body := range []string{"command-a", "command-b"} {
		go func() {
			<-start
			m, err := b.Send("codex", "claude", SendOpts{
				Body: body, ClientMessageID: "concurrent-conflict", AllowNew: true,
			})
			results <- result{body: body, message: m, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	var winner result
	switch {
	case first.err == nil && errors.Is(second.err, ErrIdempotencyConflict):
		winner = first
	case second.err == nil && errors.Is(first.err, ErrIdempotencyConflict):
		winner = second
	default:
		t.Fatalf("want one commit and one idempotency conflict, got %+v and %+v", first, second)
	}
	d, err := b.NextDelivery("claude")
	if err != nil || d == nil || len(d.Messages) != 1 || d.Messages[0].Body != winner.body ||
		d.Messages[0].MessageID != winner.message.MessageID {
		t.Fatalf("only winning command may be delivered: winner=%+v delivery=%+v err=%v", winner, d, err)
	}
}

// Slice 1 tracer bullet: an unacked delivery is returned again with the same
// delivery_id (redelivery=true); after an idempotent ack it is no longer
// returned; re-acking returns the already-advanced cursor.
func TestUnackedDeliveryIsStableAndAckIsIdempotent(t *testing.T) {
	b := open(t)

	sent, err := b.Send("codex", "claude", SendOpts{Body: "tests are green", ClientMessageID: "stable-delivery", AllowNew: true})
	if err != nil {
		t.Fatal(err)
	}

	d1, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if d1 == nil || len(d1.Messages) != 1 {
		t.Fatalf("want delivery with 1 message, got %+v", d1)
	}
	if d1.Redelivery {
		t.Error("first delivery must have redelivery=false")
	}
	if d1.Messages[0].Body != "tests are green" || d1.Messages[0].From != "codex" {
		t.Errorf("wrong message delivered: %+v", d1.Messages[0])
	}
	if d1.Through != sent.Seq {
		t.Errorf("through = %d, want %d", d1.Through, sent.Seq)
	}

	d2, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if d2 == nil || d2.ID != d1.ID {
		t.Fatalf("unacked delivery must keep a stable id: first %q, then %+v", d1.ID, d2)
	}
	if !d2.Redelivery {
		t.Error("repeated wait before ack must set redelivery=true")
	}
	if len(d2.Messages) != 1 || d2.Messages[0].Seq != d1.Messages[0].Seq {
		t.Errorf("redelivery must carry the same batch, got %+v", d2.Messages)
	}

	cursor, err := b.Ack("claude", d1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cursor != d1.Through {
		t.Errorf("ack cursor = %d, want %d", cursor, d1.Through)
	}

	cursor2, err := b.Ack("claude", d1.ID) // response lost, agent retries
	if err != nil {
		t.Fatalf("re-ack of completed delivery must succeed, got %v", err)
	}
	if cursor2 != cursor {
		t.Errorf("idempotent re-ack cursor = %d, want %d", cursor2, cursor)
	}

	d3, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if d3 != nil {
		t.Fatalf("acked delivery must not be returned again, got %+v", d3)
	}
}

// Shared identities are unsupported in M1. Stable delivery IDs preserve
// crash redelivery; they cannot distinguish a retry from a second consumer.
func TestUnsupportedSharedIdentityCanProcessTheSameDeliveryTwice(t *testing.T) {
	b := open(t)
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "side effect", ClientMessageID: "unsupported-shared-identity", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	results := make(chan *Delivery, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			d, err := b.NextDelivery("claude")
			results <- d
			errs <- err
		}()
	}
	first, second := <-results, <-results
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if first == nil || second == nil || first.ID != second.ID || len(first.Messages) != 1 || len(second.Messages) != 1 {
		t.Fatalf("shared identity limitation changed unexpectedly: first=%+v second=%+v", first, second)
	}
	if _, err := b.Ack("claude", first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", second.ID); err != nil {
		t.Fatalf("second consumer's ack is indistinguishable from an idempotent retry: %v", err)
	}
}

func TestOutstandingDeliveryAndAckSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := b.Send("codex", "claude", SendOpts{
		Body: "before restart", ClientMessageID: "restart-first", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	d1, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "claude", SendOpts{
		Body: "must not join", ClientMessageID: "restart-later",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	b, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if d2.ID != d1.ID || !d2.Redelivery || len(d2.Messages) != 1 || d2.Messages[0].Seq != first.Seq {
		t.Fatalf("restart changed outstanding membership: before=%+v after=%+v", d1, d2)
	}
	if _, err := b.Ack("claude", d2.ID); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	b, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Ack("claude", d2.ID); err != nil {
		t.Fatalf("ack retry after restart must be idempotent: %v", err)
	}
	next, err := b.NextDelivery("claude")
	if err != nil || next == nil || len(next.Messages) != 1 || next.Messages[0].Body != "must not join" {
		t.Fatalf("new mail was lost or joined old delivery: %+v %v", next, err)
	}
}
