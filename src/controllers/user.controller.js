const User = require('../models/user.model');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

/**
 * Create a new user.
 * For local login, a password is required. If provided, it will be hashed.
 */
const createUser = async (req, res) => {
    try {
      const { email, password, name, tenantId, microsoftId, roles } = req.body;
      
      // Validate required fields.
      if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
      }
      if (!tenantId) {
        return res.status(400).json({ message: 'TenantId is required.' });
      }
      // For local login, password is required.
      if (!microsoftId && !password) {
        return res.status(400).json({ message: 'Password is required for local login.' });
      }
      
      // Check if a user with this email already exists for this tenant.
      const existingUser = await User.findOne({ email, tenantId });
      if (existingUser) {
        return res.status(400).json({ message: 'User with this email already exists.' });
      }
      
      // Hash the provided password.
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = password ? await bcrypt.hash(password, salt) : undefined;
      
      // Set user status to "pending" (waiting for email confirmation)
      const status = 'pending';
      
      // Read the expiration time for the confirmation token from environment variables (in hours)
      // Default is 24 hours if not specified.
      const tokenExpiryHours = parseFloat(process.env.EMAIL_TOKEN_EXPIRATION_HOURS) || 24;
      const tokenExpiration = Date.now() + tokenExpiryHours * 60 * 60 * 1000;
      
      // Generate a secure confirmation token.
      const confirmationToken = crypto.randomBytes(20).toString('hex');
      
      // Create and save the new user.
      const newUser = new User({
        email,
        password: hashedPassword,
        name,
        tenantId,
        microsoftId,
        roles,
        status,
        resetPasswordToken: confirmationToken,
        resetPasswordExpires: tokenExpiration
      });
      
      await newUser.save();
      
      // Set up nodemailer transporter using SMTP settings from environment variables.
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
      
      // Construct the email confirmation URL.
      const confirmationUrl = `${process.env.FRONTEND_URL}/confirm-email?token=${confirmationToken}&email=${encodeURIComponent(email)}`;
      
      const mailOptions = {
        from: process.env.FROM_EMAIL,
        to: email,
        subject: 'Confirm Your Email Address',
        text: `Hello,
  
  Thank you for registering. Please confirm your account by clicking the link below:
  
  ${confirmationUrl}
  
  This link will expire in ${tokenExpiryHours} hour(s).
  
  If you did not initiate this registration, please ignore this email.
  
  Thank you.`
      };
      
      // Send the confirmation email.
      await transporter.sendMail(mailOptions);
      
      return res.status(201).json({ message: 'User created and confirmation email sent successfully.', user: newUser });
    } catch (error) {
      console.error('Error creating user:', error);
      return res.status(500).json({ message: 'Server error', error: error.message });
    }
  };

/**
 * Update an existing user.
 * If a new password is provided in the request, it will be hashed before updating.
 */
const updateUser = async (req, res) => {
  try {
    const userId = req.params.id;
    
    // If password is provided, hash it before updating.
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      req.body.password = await bcrypt.hash(req.body.password, salt);
    }
    
    const updatedUser = await User.findByIdAndUpdate(userId, req.body, { new: true });
    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found.' });
    }
    return res.status(200).json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

/**
 * Delete a user by their ID.
 */
const deleteUser = async (req, res) => {
  try {
    const userId = req.params.id;
    const deletedUser = await User.findByIdAndDelete(userId);
    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found.' });
    }
    return res.status(200).json({ message: 'User deleted successfully.' });
  } catch (error) {
    console.error('Error deleting user:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};

/**
 * Create a new user invitation.
 *
 * The endpoint expects at least:
 *   - email: user's email address
 *   - tenantId: the tenant this user belongs to
 * Optionally, it may include:
 *   - name: user's name
 *
 * It creates a new user with no password, generates an invitation token (which we reuse 
 * for password reset), and sends an email with a link where the user can set their password.
 */
const createUserInvitation = async (req, res) => {
    try {
      const { email, tenantId, name } = req.body;
  
      // Validate required fields.
      if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
      }
      if (!tenantId) {
        return res.status(400).json({ message: 'TenantId is required.' });
      }
      
      // Check if the user already exists for this tenant.
      const existingUser = await User.findOne({ email, tenantId });
      if (existingUser) {
        return res.status(400).json({ message: 'User with this email already exists.' });
      }
      
      // Generate a secure invitation token (similar to a password reset token)
      const token = crypto.randomBytes(20).toString('hex');
      // Set the token expiration (e.g., 24 hours from now)
      const tokenExpiration = Date.now() + 24 * 60 * 60 * 1000; // 24 hours in milliseconds
      
      // Create a new user with the invitation token and without a password.
      // (You can use different fields like invitationToken if preferred; here we re-use resetPasswordToken)
      const newUser = new User({
        email,
        tenantId,
        name,
        // No password yet; user will set it later
        resetPasswordToken: token,
        resetPasswordExpires: tokenExpiration
      });
      await newUser.save();
      
      // Setup nodemailer transporter using your SMTP settings from environment variables.
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT),
        secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
      
      // Construct the invitation URL.
      // The frontend should have a route like /set-password to handle completing registration.
      const invitationUrl = `${process.env.FRONTEND_URL}/set-password?token=${token}&email=${encodeURIComponent(email)}`;
      
      // Define the email options.
      const mailOptions = {
        from: process.env.FROM_EMAIL,
        to: email,
        subject: "You're invited: Set up your password",
        text: `Hello,
  
  You have been invited to join our platform. Please click on the link below to set your password and complete your registration:
  
  ${invitationUrl}
  
  This link will expire in 24 hours. If you did not request this or believe it to be in error, please ignore this email.
  
  Thank you!`
      };
      
      // Send the invitation email.
      await transporter.sendMail(mailOptions);
      return res.status(201).json({ message: 'Invitation sent successfully. Please check your email.' });
    } catch (error) {
      console.error('Error in createUserInvitation:', error);
      return res.status(500).json({ message: 'Server error', error: error.message });
    }
  };

/**
 * GET /api/users
 * Query params:
 *   page, limit, tenantId, email
 */
const getAllUsers = async (req, res) => {
  try {
    /* ---------- filters ---------- */
    const filter = {};
    if (req.query.tenantId) filter.tenantId = req.query.tenantId;
    if (req.query.email)    filter.email    = req.query.email;

    /* ---------- pagination ---------- */
    const page  = Math.max(parseInt(req.query.page,  10) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
    const skip  = (page - 1) * limit;

    /* ---------- query ---------- */
    const [totalItems, users] = await Promise.all([
      User.countDocuments(filter),
      User.find(filter)
          .populate({ path: 'roles', select: '-__v' })
          .skip(skip)
          .limit(limit)
          .lean()
    ]);

    return res.status(200).json({
      data: users,
      pagination: {
        totalItems,                        // ← renamed
        limit,
        totalPages: Math.ceil(totalItems / limit) || 1,
        currentPage: page,
        hasNextPage: page * limit < totalItems,
        hasPrevPage: page > 1
      }
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
};


module.exports = {
  createUser,
  updateUser,
  deleteUser,
  createUserInvitation,
  getAllUsers
};
