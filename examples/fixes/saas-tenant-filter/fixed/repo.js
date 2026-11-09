const r = await db.query('SELECT * FROM invoices WHERE id = $1 AND tenant_id = $2', [id, ctx.tenantId]);
