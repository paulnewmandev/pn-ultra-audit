CREATE TABLE invoices (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, amount float, status text);
CREATE TABLE accounts (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, balance numeric, api_key varchar(64), card_number varchar(19), cvv varchar(4));
