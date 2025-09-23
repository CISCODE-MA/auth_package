const express = require('express');
const router = express.Router();
const permissionController = require('../controllers/permission.controller');

// Create a new permission
router.post('/add-permission', permissionController.createPermission);

// Retrieve a list of permissions (with pagination)
router.get('/get-permission', permissionController.getPermissions);

// Update an existing permission by its ID
router.put('/update-permission/:id', permissionController.updatePermission);

// Delete a permission by its ID
router.delete('/delete-permission:id', permissionController.deletePermission);

module.exports = router;
