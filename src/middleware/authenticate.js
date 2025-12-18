// src/middleware/authenticate.js

const jwt = require('jsonwebtoken');
require('dotenv').config();

module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing or invalid Authorization header.' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      // TokenExpiredError comes here when the token is past its exp
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Access token expired.' });
      }
      return res.status(401).json({ message: 'Invalid access token.' });
    }
    // Attach the payload to req.user for downstream handlers
    req.user = decoded;
    next();
  });
};
