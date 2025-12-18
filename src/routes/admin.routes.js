const express = require('express');
const router = express.Router();
const { suspendUser } = require('../controllers/roles.controller');

// Example: PUT /api/admin/users/:id/suspend
router.put('/:id/suspend', suspendUser);

module.exports = router;
