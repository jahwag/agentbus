# Materialize mailbox receipts and group them into stable deliveries

AgentBus will persist one receipt for every message/mailbox obligation and
group offered receipts into a stable batch delivery. This replaces the earlier
global-cursor design: materialized receipts make future-only broadcast
membership, poison-message skipping, retirement, and safe pruning explicit,
while one delivery token keeps the agent-facing `wait -> process -> ack` loop
small. Per-message acknowledgement was rejected as unnecessary caller work,
and visibility-timeout leases were rejected because their clock, renewal, and
takeover machinery is unjustified while one logical consumer owns each agent
identity.
