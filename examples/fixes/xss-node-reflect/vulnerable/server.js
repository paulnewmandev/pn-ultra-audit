app.get('/hi', (req, res) => {
  res.send('<h1>' + req.query.q + '</h1>');
});
