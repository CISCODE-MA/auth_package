const Role = require('../models/role.model');

// Create a new role (accessible by superadmin only)
const createRole = async (req, res) => {
  try {
    const { tenantId, name, description, permissions } = req.body;
    if (!tenantId || !name) {
      return res.status(400).json({ message: 'tenantId and role name are required.' });
    }
    const newRole = new Role({ tenantId, name, description, permissions });
    await newRole.save();
    return res.status(201).json(newRole);
  } catch (error) {
    console.error('Error creating role:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Get all roles for a specific tenant
const getRoles = async (req, res) => {
  try {
    const { tenantId } = req.params;
    if (!tenantId) {
      return res.status(400).json({ message: 'tenantId is required in the URL.' });
    }
    const roles = await Role.paginate({ tenantId }, { page: 1, limit: 100 });
    return res.status(200).json(roles);
  } catch (error) {
    console.error('Error retrieving roles:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

const updateRole = async (req, res) => {
  try {
    const updatedRole = await Role.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updatedRole) {
      return res.status(404).json({ message: 'Role not found.' });
    }
    return res.status(200).json(updatedRole);
  } catch (error) {
    console.error('Error updating role:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

const deleteRole = async (req, res) => {
  try {
    const deletedRole = await Role.findByIdAndDelete(req.params.id);
    if (!deletedRole) {
      return res.status(404).json({ message: 'Role not found.' });
    }
    return res.status(200).json({ message: 'Role deleted successfully.' });
  } catch (error) {
    console.error('Error deleting role:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

/**
 * suspendUser
 * 
 * This controller sets a user's status to "suspended". It expects:
 * - The authenticated user's info in req.user.
 * - The target user's id in req.params.id.
 * 
 * Only a superadmin (a user whose roles include "superadmin") is authorized
 * to perform this action.
 */
const suspendUser = async (req, res) => {
  try {
    // Ensure the authenticated user is provided.
    if (!req.user || !req.user.roles) {
      return res.status(403).json({ message: 'Access denied. Superadmin privileges required.' });
    }

    // Check if the current user has the superadmin role.
    // (Adjust this check if your roles are stored as ObjectIds or have different structure.)
    if (!req.user.roles.includes("superadmin")) {
      return res.status(403).json({ message: 'Access denied. Superadmin privileges required.' });
    }

    // Extract the target user's ID from the URL.
    const { id } = req.params;
    if (!id) {
      return res.status(400).json({ message: 'User ID is required in the URL.' });
    }

    // Update the target user's status to "suspended"
    const updatedUser = await User.findByIdAndUpdate(id, { status: 'suspended' }, { new: true });
    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found.' });
    }

    return res.status(200).json({ message: 'User suspended successfully.', user: updatedUser });
  } catch (error) {
    console.error('Error suspending user:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

module.exports = {
  createRole,
  getRoles,
  updateRole,
  deleteRole,
  suspendUser
};
