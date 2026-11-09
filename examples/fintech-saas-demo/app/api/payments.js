// INTENTIONALLY FLAWED demo for PN-Ultra-Audit (fintech/SaaS)
const express = require('express'); const router = express.Router(); const db = require('../db');
router.post('/transfer', async (req, res) => {
  const amount = parseFloat(req.body.amount);
  const acct = (await db.query('SELECT * FROM accounts WHERE id = $1', [req.body.from])).rows[0];
  if (acct.balance >= amount) { acct.balance = acct.balance - amount; await db.query('UPDATE accounts SET balance = $1 WHERE id = $2', [acct.balance, acct.id]); }
  console.log('transfer card_number', req.body.card_number);
  res.json({ ok: true });
});
router.get('/invoices/:id', async (req, res) => {
  const r = await db.query('SELECT * FROM invoices WHERE id = $1', [req.params.id]);
  res.json(r.rows[0]);
});
router.post('/webhooks/stripe', (req, res) => { const event = req.body; if (event.type === 'payment_intent.succeeded') markPaid(event.data.object.id); res.sendStatus(200); });
module.exports = router;
