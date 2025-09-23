const Permission = require('../models/permission.model');

/**
 * Create a new permission.
 * Expects request body to include at least "name" (and optionally "description").
 */
const createPermission = async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name) {
      return res.status(400).json({ message: 'Permission name is required.' });
    }

    const newPermission = new Permission({ name, description });
    await newPermission.save();
    return res.status(201).json(newPermission);
  } catch (error) {
    console.error('Error creating permission:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

/**
 * Retrieve a list of permissions.
 * Supports pagination via query parameters (page & limit).
 */
const getPermissions = async (req, res) => {
  try {
    const { page, limit } = req.query;
    const permissions = await Permission.paginate({}, {
      page: parseInt(page) || 1,
      limit: parseInt(limit) || 10
    });
    return res.status(200).json(permissions);
  } catch (error) {
    console.error('Error retrieving permissions:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

/**
 * Update a permission by its ID.
 * Expects new values in the request body.
 */
const updatePermission = async (req, res) => {
  try {
    const { id } = req.params;
    const updatedPermission = await Permission.findByIdAndUpdate(id, req.body, { new: true });
    if (!updatedPermission) {
      return res.status(404).json({ message: 'Permission not found.' });
    }
    return res.status(200).json(updatedPermission);
  } catch (error) {
    console.error('Error updating permission:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

/**
 * Delete a permission by its ID.
 */
const deletePermission = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedPermission = await Permission.findByIdAndDelete(id);
    if (!deletedPermission) {
      return res.status(404).json({ message: 'Permission not found.' });
    }
    return res.status(200).json({ message: 'Permission deleted successfully.' });
  } catch (error) {
    console.error('Error deleting permission:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

module.exports = {
  createPermission,
  getPermissions,
  updatePermission,
  deletePermission
};
