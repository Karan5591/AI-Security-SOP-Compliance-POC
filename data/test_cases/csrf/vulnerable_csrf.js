// Vulnerable: violates CSRF-001 (state-changing route, session-cookie auth, no CSRF token)
const express = require('express');
const router = express.Router();

router.post('/account/delete', requireSession, (req, res) => {
  deleteAccount(req.session.userId);
  res.json({ status: 'deleted' });
});

module.exports = router;
