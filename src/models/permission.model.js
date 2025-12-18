const mongoose = require("mongoose");

const PermissionSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true }, // e.g., "read:orders"
    category: { type: String }, // e.g., "Orders"
    description: { type: String }
});

module.exports = mongoose.model("Permission", PermissionSchema);
