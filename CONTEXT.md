# AgentBus

AgentBus owns durable mail exchange between ephemeral coding-agent sessions.
It distinguishes an addressed obligation from the immutable message content
so delivery and retention remain explicit.

## Language

**Principal**:
An agent or operator whose authority has been resolved by a trusted adapter.
_Avoid_: Caller, claimed user

**Mailbox**:
A durable named address that can be reserved, active, or retired.
_Avoid_: Agent record, subscription

**Reserved mailbox**:
A direct-mail address that exists but has not yet been activated by its owner.
It is not a broadcast recipient.
_Avoid_: Phantom identity, inactive agent

**Active mailbox**:
A mailbox whose owner has acted or been provisioned and which participates in
future broadcasts.
_Avoid_: Online agent, registered session

**Message**:
Immutable content authored once by a principal and identified independently of
any recipient's delivery state.
_Avoid_: Delivery, event

**Receipt**:
One mailbox's durable obligation for one message, settled by acknowledgement or
an audited dead-letter decision.
_Avoid_: Cursor entry, subscription offset

**Delivery**:
An immutable ordered batch of offered receipts presented to one mailbox under
one acknowledgement token.
_Avoid_: Message, lease, cursor

**Redelivery**:
A repeated presentation of an unacknowledged delivery; it does not prove the
earlier presentation reached or was processed by an agent.
_Avoid_: Retry guarantee, duplicate message

**Dead letter**:
A receipt deliberately settled without agent acknowledgement, together with an
operator-supplied reason.
_Avoid_: Deleted message, failed send

**Retirement**:
The terminal transition that prevents a mailbox from acting or receiving new
mail and dead-letters its unsettled receipts.
_Avoid_: Offline, deletion

**Operator session**:
A short-lived browser capability restricted to read-only inspection of retained
AgentBus state.
_Avoid_: Admin session, browser admin credential

**Content reveal**:
An explicit operator request to inspect one retained message's untrusted body
and structured data.
_Avoid_: Expanded row, hidden content
