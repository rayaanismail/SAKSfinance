DELETE FROM transactions WHERE user_id IN (
    SELECT id FROM users Where username='josh'
);

DELETE FROM ownership WHERE user_id IN (
    SELECT id FROM users Where username='josh'
);

DELETE FROM users WHERE username='josh';
