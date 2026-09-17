// Secure: HTML-encodes reflected user input, satisfies XSS-002 / XSS-004
const express = require('express');
const escapeHtml = require('escape-html');
const router = express.Router();

router.get('/search', (req, res) => {
  res.send(`<h1>Results for: ${escapeHtml(req.query.q)}</h1>`);
});

module.exports = router;
