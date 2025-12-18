const express = require('express');
const router = express.Router();
const passwordResetController = require('../controllers/passwordReset.controller');

router.post('/forgot-password', passwordResetController.requestPasswordReset);
router.post('/reset-password', passwordResetController.resetPassword);

module.exports = router;
