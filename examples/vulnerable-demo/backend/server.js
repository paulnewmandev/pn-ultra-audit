const express = require('express'); const jwt = require('jsonwebtoken'); const { exec } = require('child_process');
const app = express();
app.use(require('cors')({ origin: '*' }));
app.get('/hello', (req, res) => { res.send('<h1>Hello ' + req.query.name + '</h1>'); });
app.get('/u', async (req, res) => { const { id } = req.query; const r = await db.query(`SELECT * FROM users WHERE id = ${id}`); res.json(r); });
app.get('/run', (req, res) => { exec('ls ' + req.query.dir, (e, o) => res.send(o)); });
app.post('/login', (req, res) => { const t = jwt.sign({ u: req.body.u }, 'hardcodedjwtsecret'); res.json({ t }); });
app.get('/item/:id', async (req, res) => { const it = await Item.findById(req.params.id); res.json(it); });
const token = Math.random().toString(36); // reset token
['a','b'].forEach(async (x) => { await save(x); });
app.listen(3000);
