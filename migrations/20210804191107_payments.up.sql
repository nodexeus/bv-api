-- Add up migration script here
CREATE TABLE IF NOT EXISTS payments (
    hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL,
    block BIGINT NOT NULL,
    payer TEXT NOT NULL,
    payee TEXT NOT NULL,
    amount BIGINT NOT NULL,
    oracle_price BIGINT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT fk_payments_users FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
);
CREATE INDEX idx_payments_payer ON payments(payer);
CREATE INDEX idx_paymets_payee on payments(payee);
CREATE index idx_payments_user_id ON payments(user_id);