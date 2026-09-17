// Secure: verifies the caller owns the resource, satisfies BAC-001 / BAC-002
const express = require('express');
const router = express.Router();

router.get('/calendar/:userId', requireAuth, async (req, res) => {
  if (req.params.userId !== req.user.id) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const calendar = await getCalendar(req.params.userId);
  res.json(calendar);
});

module.exports = router;
