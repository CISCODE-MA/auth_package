const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

const ClientSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  // Hashed password; may be empty for social/OAuth clients
  password: {
    type: String,
    required: function () {
      return !this.microsoftId && !this.googleId && !this.facebookId;
    }
  },
  name: { type: String },

  // Social providers (optional)
  microsoftId: { type: String, index: true },
  googleId: { type: String, index: true },
  facebookId: { type: String, index: true },

  // Roles assigned to the client
  roles: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Role' }],

  // Password reset
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },

  // For refresh flow (your controller already sets this)
  refreshToken: { type: String },

  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

ClientSchema.plugin(mongoosePaginate);

module.exports = mongoose.model('Client', ClientSchema);
