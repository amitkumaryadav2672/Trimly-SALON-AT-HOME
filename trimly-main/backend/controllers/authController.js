const jwt = require('jsonwebtoken');
const User = require('../models/User');
const asyncHandler = require('../utils/asyncHandler');
const ErrorResponse = require('../utils/errorResponse');
const { auditLogger } = require('../utils/auditLogger');
const { sendPasswordResetEmail, isResetTokenValid, clearResetToken } = require('../utils/passwordReset');
const { validatePasswordStrength } = require('../utils/validators');
const {
  normalizeEmail,
  isEmailIdentifier,
  buildPhoneLookupQuery,
  resolveLoginIdentifier,
  resolveRegistrationIdentifiers
} = require('../utils/authIdentity');

// Authentication controller for register/login/session lookup and token lifecycle.
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

const signToken = (user) => {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not configured');
  }

  const token = jwt.sign(
    { id: user._id, role: user.role }, 
    process.env.JWT_SECRET, 
    { expiresIn: JWT_EXPIRES_IN }
  );

  // Ensure auditLogger exists before using
  if (auditLogger && typeof auditLogger.log === 'function') {
    auditLogger.log(
      'AUTHENTICATION', 
      'TOKEN_ISSUED', 
      `Issued JWT for user=${user._id.toString()} role=${user.role}`,
      { userId: user._id, role: user.role }
    );
  } else {
    console.log(`[auth] Issued JWT for user=${user._id.toString()} role=${user.role}`);
  }

  return token;
};

const sanitizeUser = (userDoc) => ({
  id: userDoc._id,
  _id: userDoc._id,
  name: userDoc.name,
  firstName: userDoc.firstName || '',
  lastName: userDoc.lastName || '',
  phone: userDoc.phone,
  email: userDoc.email || '',
  role: userDoc.role,
  status: userDoc.status,
  isAvailable: userDoc.isAvailable !== false,
  approved: userDoc.approved,
  isApproved: userDoc.isApproved
});

const canRegisterAdmin = async (adminKey = '') => {
  const adminCount = await User.countDocuments({ role: 'admin' });
  if (adminCount === 0) return true;

  const expectedKey = process.env.ADMIN_REGISTRATION_KEY;
  return !!(expectedKey && adminKey && adminKey === expectedKey);
};

const escapeRegex = (value = '') =>
  String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const findUserByLoginIdentifier = async (loginId = '') => {
  const identifier = String(loginId || '').trim();
  if (!identifier) return null;

  if (isEmailIdentifier(identifier)) {
    const normalized = normalizeEmail(identifier);
    const userByEmail = await User.findOne({ email: normalized });
    if (userByEmail) return userByEmail;

    // Legacy compatibility: older records may have email in the `phone` field.
    let userByLegacyPhone = await User.findOne(buildPhoneLookupQuery(normalized));
    if (!userByLegacyPhone && normalized !== identifier) {
      userByLegacyPhone = await User.findOne(buildPhoneLookupQuery(identifier));
    }
    if (!userByLegacyPhone) {
      userByLegacyPhone = await User.findOne({
        phone: { $regex: new RegExp(`^${escapeRegex(identifier)}$`, 'i') }
      });
    }
    return userByLegacyPhone;
  }

  return User.findOne(buildPhoneLookupQuery(identifier));
};

// @desc    Register new user
// @route   POST /api/auth/register
// @access  Public
exports.register = asyncHandler(async (req, res, next) => {
  const { name, firstName, lastName, phone, email, identifier, password, role, adminKey } = req.body;
  const { normalizedPhone, normalizedEmail } = resolveRegistrationIdentifiers({
    phone,
    email,
    identifier
  });

  // 🔍 DEBUG: Log registration attempt
  console.log('\n========== 📝 REGISTRATION ATTEMPT ==========');
  console.log('📝 Name:', name || firstName);
  console.log('📝 Phone:', normalizedPhone);
  console.log('📝 Email:', normalizedEmail || 'Not provided');
  console.log('📝 Role:', role || 'user');
  console.log('📝 Password length:', password ? password.length : 0);
  console.log('===========================================\n');

  if ((!name && !firstName) || !normalizedPhone || !password) {
    console.log('❌ Validation failed: Missing required fields');
    return next(new ErrorResponse('Name, phone and password are required', 400));
  }

  // Check password strength
  const passwordError = validatePasswordStrength(password);
  if (passwordError) {
    console.log('❌ Password validation failed:', passwordError);
    if (auditLogger && typeof auditLogger.log === 'function') {
      auditLogger.log('SECURITY', 'WEAK_PASSWORD_ATTEMPT', 'User attempted registration with weak password', { phone: normalizedPhone });
    }
    return next(new ErrorResponse(passwordError, 400));
  }

  const safeRole = ['user', 'provider', 'admin'].includes(role) ? role : 'user';
  console.log('🔧 Safe role set to:', safeRole);

  // ADMIN CHECK IS DISABLED - Any role can register including admin
  // if (safeRole === 'admin') {
  //   const allowed = await canRegisterAdmin(adminKey);
  //   if (!allowed) {
  //     if (auditLogger && typeof auditLogger.log === 'function') {
  //       auditLogger.log('SECURITY', 'UNAUTHORIZED_ADMIN_REGISTRATION', 'Unauthorized attempt to register as admin', { phone: normalizedPhone });
  //     }
  //     return next(new ErrorResponse('Admin registration is restricted', 403));
  //   }
  // }

  // Check if user exists by phone
  console.log('🔍 Checking if phone exists:', normalizedPhone);
  let existing = await User.findOne(buildPhoneLookupQuery(normalizedPhone));
  if (existing) {
    console.log('❌ Phone already exists in database:', normalizedPhone);
    console.log('   Existing user ID:', existing._id);
    console.log('   Existing user role:', existing.role);
    return next(new ErrorResponse('Phone number already registered', 409));
  }
  console.log('✅ Phone is available:', normalizedPhone);

  // Check if user exists by email
  if (normalizedEmail) {
    console.log('🔍 Checking if email exists:', normalizedEmail);
    existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      console.log('❌ Email already exists in database:', normalizedEmail);
      console.log('   Existing user ID:', existing._id);
      console.log('   Existing user role:', existing.role);
      return next(new ErrorResponse('Email already registered', 409));
    }
    console.log('✅ Email is available:', normalizedEmail);
  }

  console.log('✅ All checks passed, creating new user...');
  
  const hashed = await User.hashPassword(password);
  console.log('🔐 Password hashed successfully');

  const user = await User.create({
    name: name || `${firstName || ''} ${lastName || ''}`.trim(),
    firstName,
    lastName,
    phone: normalizedPhone,
    email: normalizedEmail || undefined,
    password: hashed,
    role: safeRole,
    status: safeRole === 'provider' ? 'pending' : 'active',
    approved: safeRole !== 'provider',
    isApproved: safeRole !== 'provider',
    verified: safeRole !== 'provider'
  });

  console.log('✅ USER CREATED SUCCESSFULLY!');
  console.log('   User ID:', user._id);
  console.log('   User Role:', user.role);
  console.log('   User Name:', user.name);
  console.log('===========================================\n');

  // SECURITY: Log successful registration
  if (auditLogger && typeof auditLogger.log === 'function') {
    auditLogger.log('AUTHENTICATION', 'USER_REGISTERED', 'New user registered successfully', { userId: user._id, role: safeRole });
  }

  const shouldIssueToken = !(safeRole === 'provider' && (!user.approved || !user.isApproved || user.status !== 'active'));
  const token = shouldIssueToken ? signToken(user) : null;
  const message =
    safeRole === 'provider' && !token
      ? 'Provider registered and awaiting approval'
      : 'User registered successfully';

  res.status(201).json({
    success: true,
    message,
    data: { token, user: sanitizeUser(user) }
  });
});

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = asyncHandler(async (req, res, next) => {
  const { phone, email, identifier, password } = req.body;
  const loginId = resolveLoginIdentifier({ identifier, phone, email });
  
  console.log('\n========== 🔐 LOGIN ATTEMPT ==========');
  console.log('📝 Login ID:', loginId);
  console.log('=====================================\n');
  
  if (!loginId || !password) {
    return next(new ErrorResponse('Phone/Email and password are required', 400));
  }

  const user = await findUserByLoginIdentifier(loginId);
  
  if (!user) {
    console.log('❌ User not found:', loginId);
    // SECURITY: Log failed login attempt
    if (auditLogger && typeof auditLogger.log === 'function') {
      auditLogger.log('AUTHENTICATION', 'LOGIN_FAILED', 'Login attempt with non-existent user', { identifier: loginId, ip: req.ip });
    }
    return next(new ErrorResponse('Invalid credentials', 401));
  }

  console.log('✅ User found:', user._id, user.role);

  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    console.log('❌ Password mismatch for user:', user._id);
    // SECURITY: Log failed password attempt
    if (auditLogger && typeof auditLogger.log === 'function') {
      auditLogger.log('AUTHENTICATION', 'LOGIN_FAILED', 'Login attempt with wrong password', { userId: user._id, ip: req.ip });
    }
    return next(new ErrorResponse('Invalid credentials', 401));
  }

  console.log('✅ Password matched');

  if (user.role === 'provider' && (!user.approved || !user.isApproved || user.status !== 'active')) {
    console.log('❌ Provider account not approved:', user._id);
    return next(new ErrorResponse('Provider account is pending approval', 403));
  }

  if (['inactive', 'suspended', 'rejected'].includes(user.status)) {
    console.log('❌ Account not active:', user._id, user.status);
    // SECURITY: Log attempt to login with inactive account
    if (auditLogger && typeof auditLogger.log === 'function') {
      auditLogger.log('AUTHENTICATION', 'LOGIN_FAILED', `Login attempt with ${user.status} account`, { userId: user._id, status: user.status, ip: req.ip });
    }
    return next(new ErrorResponse('Account is not active', 403));
  }

  const token = signToken(user);
  console.log('✅ Login successful for user:', user._id);
  console.log('=====================================\n');

  // SECURITY: Log successful login
  if (auditLogger && typeof auditLogger.log === 'function') {
    auditLogger.log('AUTHENTICATION', 'LOGIN_SUCCESS', 'User logged in successfully', { userId: user._id, role: user.role, ip: req.ip });
  }

  res.status(200).json({
    success: true,
    message: 'Logged in',
    data: { token, user: sanitizeUser(user) }
  });
});

// @desc    Forgot password - Generate and send secure reset token
// @route   POST /api/auth/forgot-password
// @access  Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  const { email, phone, identifier } = req.body;
  const loginId = resolveLoginIdentifier({ identifier, phone, email });

  if (!loginId) {
    return next(new ErrorResponse('Please provide your email or phone number', 400));
  }

  const user = await findUserByLoginIdentifier(loginId);
  if (!user) {
    // SECURITY: Don't reveal if user exists or not
    // Return success to prevent user enumeration
    if (auditLogger && typeof auditLogger.log === 'function') {
      auditLogger.log('SECURITY', 'PASSWORD_RESET_ATTEMPT', 'Password reset attempt for non-existent user', { identifier: loginId });
    }
    return res.status(200).json({
      success: true,
      message: 'If an account exists with this email/phone, you will receive a password reset link'
    });
  }

  // Check if user has email (required for password reset)
  if (!user.email) {
    if (auditLogger && typeof auditLogger.log === 'function') {
      auditLogger.log('SECURITY', 'PASSWORD_RESET_FAILED', 'Password reset attempt for user without email', { userId: user._id });
    }
    return res.status(400).json({
      success: false,
      message: 'This account does not have an email address. Please contact support.'
    });
  }

  // CRITICAL: Generate secure reset token
  const resetToken = user.generatePasswordResetToken();
  
  // Save the token hash and expiration to database
  await user.save();

  // SECURITY: Send password reset email with token
  try {
    await sendPasswordResetEmail(user, resetToken);
    
    if (auditLogger && typeof auditLogger.log === 'function') {
      auditLogger.log('AUTHENTICATION', 'PASSWORD_RESET_REQUESTED', 'Password reset email sent', { userId: user._id, email: user.email });
    }
    
    return res.status(200).json({
      success: true,
      message: 'Password reset link sent to your email'
    });
  } catch (emailError) {
    // Clear the reset token if email send fails
    clearResetToken(user);
    await user.save();
    
    console.error('Password reset email failed:', emailError.message);
    if (auditLogger && typeof auditLogger.log === 'function') {
      auditLogger.log('SECURITY', 'PASSWORD_RESET_EMAIL_FAILED', `Failed to send reset email: ${emailError.message}`, { userId: user._id });
    }
    
    return next(new ErrorResponse('Failed to send reset email. Please try again later.', 500));
  }
});

// @desc    Reset password using secure token
// @route   POST /api/auth/reset-password
// @access  Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  const { token, newPassword, confirmPassword } = req.body;

  // Validate inputs
  if (!token || !newPassword || !confirmPassword) {
    return next(new ErrorResponse('Token and new password are required', 400));
  }

  // Validate password confirmation
  if (newPassword !== confirmPassword) {
    return next(new ErrorResponse('Passwords do not match', 400));
  }

  // Validate password strength
  const passwordError = validatePasswordStrength(newPassword);
  if (passwordError) {
    return next(new ErrorResponse(passwordError, 400));
  }

  // Find user with valid reset token
  // Note: We search by the hashed token which is stored in DB
  const crypto = require('crypto');
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  if (!user) {
    if (auditLogger && typeof auditLogger.log === 'function') {
      auditLogger.log('SECURITY', 'INVALID_RESET_TOKEN', 'Invalid or expired password reset token used', { token: token.substring(0, 10) });
    }
    return next(new ErrorResponse('Invalid or expired reset token', 400));
  }

  // CRITICAL: Hash and set new password
  const hashedPassword = await User.hashPassword(newPassword);
  user.password = hashedPassword;
  
  // Clear reset token after successful reset
  clearResetToken(user);
  
  // Save updated user
  await user.save();

  // SECURITY: Log successful password reset
  if (auditLogger && typeof auditLogger.log === 'function') {
    auditLogger.log('AUTHENTICATION', 'PASSWORD_RESET_SUCCESS', 'Password reset completed successfully', { userId: user._id, email: user.email });
  }

  // Return success message (don't auto-login for security)
  res.status(200).json({
    success: true,
    message: 'Password reset successfully. Please login with your new password.'
  });
});

// @desc    Logout user
// @route   POST /api/auth/logout
// @access  Private
exports.logout = asyncHandler(async (req, res, next) => {
  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
});

// @desc    Refresh auth token
// @route   POST /api/auth/refresh
// @access  Private
exports.refreshToken = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user) {
    return next(new ErrorResponse('User not found', 404));
  }

  const token = signToken(user);
  res.status(200).json({
    success: true,
    message: 'Token refreshed',
    data: { token }
  });
});

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
exports.getMe = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id).select('-password');
  if (!user) {
    return next(new ErrorResponse('User not found', 404));
  }
  res.status(200).json({
    success: true,
    message: 'Profile retrieved',
    data: sanitizeUser(user)
  });
});