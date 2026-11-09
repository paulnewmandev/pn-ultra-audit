app.get('/u', async (req, res) => {
  const { id } = req.query;
  const r = await db.query('SELECT * FROM users WHERE id = $1', [id]);
  res.json(r.rows);
});
