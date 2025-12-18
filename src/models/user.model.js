const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true
  },
  // Hashed password; may be empty for social/OAuth accounts.
  password: {
    type: String,
    required: function () {
      // Require a password ONLY if no social provider
      return !this.microsoftId && !this.googleId && !this.facebookId;
    }
  },
  name: { type: String },

  // IMPORTANT: still required for staff
  tenantId: { type: String, required: true },

  // Social providers (all optional)
  microsoftId: { type: String, index: true },
  googleId: { type: String, index: true },
  facebookId: { type: String, index: true },

  // Roles: array of Role ObjectIds
  roles: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Role' }],

  // Password reset
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },

  status: {
    type: String,
    enum: ['pending', 'active', 'suspended', 'deactivated'],
    default: 'pending'
  },

  // Refresh token storage
  refreshToken: { type: String },

  // ─── Lockout fields ────────────────────────────────────────
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date }
}, { timestamps: true });

UserSchema.plugin(mongoosePaginate);

module.exports = mongoose.model('User', UserSchema);
