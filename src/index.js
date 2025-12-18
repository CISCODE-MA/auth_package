const express = require('express');
const connectDB = require('./config/db.config');
require('dotenv').config();

// Import routes
const authRoutes            = require('./routes/auth.routes');
const passwordResetRoutes   = require('./routes/passwordReset.routes');
const rolesRoutes           = require('./routes/roles.routes');
const permissionsRoutes     = require('./routes/permission.routes');
const adminRoutes           = require('./routes/admin.routes');
const userRoutes            = require('./routes/user.routes');

const app = express();

app.use(express.json());
connectDB();

// Auth endpoints
app.use('/api/auth', authRoutes);
app.use('/api/auth', passwordResetRoutes);

// User management endpoints
app.use('/api/users', userRoutes);

// Role & Permission endpoints
app.use('/api/auth/permissions', permissionsRoutes);      // permissions under /api/auth/roles
app.use('/api/auth/roles', rolesRoutes);            // roles under /api/auth/roles

// Admin‐only endpoints
app.use('/api/admin', adminRoutes);

module.exports = app;
