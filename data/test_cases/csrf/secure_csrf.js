// Secure: requires a CSRF token on the state-changing route, satisfies CSRF-001
const express = require('express');
const csrfProtection = require('./middleware/csrf');
const router = express.Router();

router.post('/account/delete', requireSession, csrfProtection, (req, res) => {
  deleteAccount(req.session.userId);
  res.json({ status: 'deleted' });
});

module.exports = router;
