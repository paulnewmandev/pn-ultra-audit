const escapeHtml = require('escape-html');
app.get('/hi', (req, res) => {
  res.send('<h1>' + escapeHtml(req.query.q) + '</h1>');
});
