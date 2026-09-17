// Vulnerable: violates SQL-001 / SQL-002 (string interpolation with user-controlled input)
const express = require('express');
const router = express.Router();

router.get('/users/:userId', async (req, res) => {
  const userId = req.params.userId;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  const result = await pool.query(query);
  res.json(result.rows);
});

module.exports = router;
