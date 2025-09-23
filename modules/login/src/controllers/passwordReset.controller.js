const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const User = require('../models/user.model');
const Client = require('../models/client.model');

// Utility to choose the right model
const getModel = (type) => {
  switch (type) {
    case 'user':
      return User;
    case 'client':
      return Client;
    default:
      throw new Error('Invalid account type');
  }
};

// ─── Request Password Reset ────────────────────────────────
const requestPasswordReset = async (req, res) => {
  try {
    const { email, type } = req.body;

    if (!email || !type) {
      return res.status(400).json({ message: 'Email and type are required.' });
    }

    const Model = getModel(type);
    const account = await Model.findOne({ email });

    if (!account) {
      // Security: don't reveal existence
      return res.status(200).json({
        message:
          'If that email address is in our system, a password reset link has been sent.'
      });
    }

    const token = crypto.randomBytes(20).toString('hex');
    account.resetPasswordToken = token;
    account.resetPasswordExpires = Date.now() + 3600000; // 1h

    // Use updateOne if tenantId or required fields cause validation issues
    await account.save();

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}&type=${type}`;

    const mailOptions = {
      from: process.env.FROM_EMAIL,
      to: account.email,
      subject: 'Password Reset',
      text: `You are receiving this email because you (or someone else) requested a password reset.
Please click the link below, or paste it into your browser:
${resetUrl}

If you did not request this, please ignore this email.
This link will expire in 1 hour.`
    };

    await transporter.sendMail(mailOptions);

    return res.status(200).json({
      message:
        'If that email address is in our system, a password reset link has been sent.'
    });
  } catch (error) {
    console.error('Error in requestPasswordReset:', error);
    return res
      .status(500)
      .json({ message: 'Server error', error: error.message });
  }
};

// ─── Reset Password ────────────────────────────────
const resetPassword = async (req, res) => {
  try {
    const { token, newPassword, type } = req.body;

    if (!token || !newPassword || !type) {
      return res
        .status(400)
        .json({ message: 'Token, new password, and type are required.' });
    }

    const Model = getModel(type);

    const account = await Model.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!account) {
      return res.status(400).json({ message: 'Invalid or expired token.' });
    }

    const salt = await bcrypt.genSalt(10);
    account.password = await bcrypt.hash(newPassword, salt);
    account.resetPasswordToken = undefined;
    account.resetPasswordExpires = undefined;

    await account.save();

    return res
      .status(200)
      .json({ message: 'Password has been reset successfully.' });
  } catch (error) {
    console.error('Error in resetPassword:', error);
    return res
      .status(500)
      .json({ message: 'Server error', error: error.message });
  }
};

module.exports = {
  requestPasswordReset,
  resetPassword
};
