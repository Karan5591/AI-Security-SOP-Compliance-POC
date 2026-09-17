// Secure: parameterized query via node-postgres, satisfies SQL-001 / SQL-002
const express = require('express');
const router = express.Router();

router.get('/users/:userId', async (req, res) => {
  const userId = req.params.userId;
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  res.json(result.rows);
});

module.exports = router;
