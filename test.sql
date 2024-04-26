CREATE TABLE transactions (transaction_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, user_id INTEGER NOT NULL, symbol TEXT NOT NULL, unit_price NUMERIC NOT NULL DEFAULT 0, shares INTEGER NOT NULL, price NUMERIC NOT NULL DEFAULT 0, purchase_time TIMESTAMP NOT NULL);

CREATE UNIQUE INDEX transaction_id ON transactions (transaction_id);
