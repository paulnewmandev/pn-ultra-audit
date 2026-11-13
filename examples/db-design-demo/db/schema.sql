CREATE TABLE accounts (id INT PRIMARY KEY, uuid CHAR(36), owner_id INT, balance DOUBLE, created_at TIMESTAMP);
CREATE TABLE invoices (id INT PRIMARY KEY, account_id INT, amount DECIMAL(12,2), created_at TIMESTAMP);
CREATE INDEX i1 ON invoices(account_id);
CREATE INDEX i2 ON invoices(account_id, created_at);
