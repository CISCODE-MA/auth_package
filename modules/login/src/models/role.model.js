const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

const RoleSchema = new mongoose.Schema({
  tenantId: { type: String, required: true },
  name: { type: String, required: true, unique: true },
  description: { type: String },
  // Permissions stored as strings (e.g., "create:invoice", "delete:user")
  permissions: [{ type: String }]
}, { timestamps: true });

RoleSchema.plugin(mongoosePaginate);

module.exports = mongoose.model('Role', RoleSchema);
