const Role = require("../models/role.model");

// Middleware to check if user has required permission
const hasPermission = (requiredPermission) => {
    return async (req, res, next) => {
        try {
            const { tenantId, roleIds } = req.user;

            // Fetch roles from DB
            const roles = await Role.find({ _id: { $in: roleIds }, tenantId });
            const permissions = roles.flatMap(role => role.permissions);

            if (permissions.includes(requiredPermission)) {
                return next();
            }

            res.status(403).json({ error: "Forbidden: Insufficient permissions" });
        } catch (error) {
            res.status(500).json({ error: "Authorization error" });
        }
    };
};

module.exports = { hasPermission };
