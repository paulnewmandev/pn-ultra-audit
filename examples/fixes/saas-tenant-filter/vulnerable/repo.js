const r = await db.query('SELECT * FROM invoices WHERE id = $1', [id]);
