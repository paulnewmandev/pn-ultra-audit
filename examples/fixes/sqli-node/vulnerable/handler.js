app.get('/u', async (req, res) => {
  const { id } = req.query;
  const r = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(r.rows);
});
