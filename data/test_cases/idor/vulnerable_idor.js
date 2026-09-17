// Vulnerable: violates BAC-001 / BAC-002 (no ownership check, trusts the path param)
const express = require('express');
const router = express.Router();

router.get('/calendar/:userId', async (req, res) => {
  const calendar = await getCalendar(req.params.userId);
  res.json(calendar);
});

module.exports = router;
