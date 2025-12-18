const express = require('express');
const router = express.Router();
const rolesController = require('../controllers/roles.controller');

// These endpoints should be protected and accessible only by a superadmin
router.post('/', rolesController.createRole);
router.get('/:tenantId', rolesController.getRoles);
router.put('/:id', rolesController.updateRole);
router.delete('/:id', rolesController.deleteRole);

module.exports = router;
