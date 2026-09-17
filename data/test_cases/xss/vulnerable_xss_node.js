// Vulnerable: violates XSS-002 / XSS-004 (unescaped user input reflected into HTML)
const express = require('express');
const router = express.Router();

router.get('/search', (req, res) => {
  res.send(`<h1>Results for: ${req.query.q}</h1>`);
});

module.exports = router;
