// src/routes/user.routes.js

const express = require('express');
const router = express.Router();
const userController = require('../controllers/user.controller');

// Fetch all users (optionally filtered via query params)
router.get('/', userController.getAllUsers);

// Create a new user (with immediate password or MSFT ID)
router.post('/', userController.createUser);

// Update an existing user
router.put('/:id', userController.updateUser);

// Delete a user by ID
router.delete('/:id', userController.deleteUser);

// Send an invitation email (no password yet)
router.post('/invite', userController.createUserInvitation);

module.exports = router;
