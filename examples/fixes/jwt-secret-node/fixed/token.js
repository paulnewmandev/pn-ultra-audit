const jwt = require('jsonwebtoken');
const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '15m' });
