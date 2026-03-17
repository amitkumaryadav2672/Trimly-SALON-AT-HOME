const validator = require('email-validator');
const { parsePhoneNumber, isValidPhoneNumber } = require('libphonenumber-js');

/**
 * Validate email format using industry standard
 */
const validateEmail = (email) => {
  if (!email || typeof email !== 'string') return false;
  
  const normalized = email.trim().toLowerCase();
  
  // Check length
  if (normalized.length > 254) return false;
  
  // Use industry-standard validation
  return validator.validate(normalized);
};

/**
 * Validate and normalize phone numbers
 */
const validatePhoneNumber = (phone) => {
  if (!phone || typeof phone !== 'string') return null;
  
  try {
    // Try parsing with default region (India - adjust as needed)
    const parsed = parsePhoneNumber(phone, 'IN');
    
    if (!parsed || !parsed.isValid()) {
      return null;
    }
    
    return parsed.format('E.164'); // Returns +91XXXXXXXXXX format
  } catch (error) {
    return null;
  }
};

/**
 * Sanitize strings to prevent NoSQL injection
 */
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  // Remove dangerous MongoDB operators
  return input
    .replace(/[{}$]/g, '')
    .replace(/mongodb/gi, '')
    .trim()
    .substring(0, 500); // Limit length
};

/**
 * Validate password strength - COMPLETELY FLEXIBLE
 * Users can create ANY password they want with NO RESTRICTIONS
 */
const validatePasswordStrength = (password) => {
  // Just check if password exists
  if (!password || typeof password !== 'string') {
    return 'Password is required';
  }
  
  // Only check that it's not empty
  if (password.trim().length === 0) {
    return 'Password cannot be empty';
  }
  
  // ALL PASSWORDS ARE ACCEPTED - no length limits, no character requirements
  // Users can use: "123", "abc", "password", "Amit@1234", "sunita", anything!
  
  return null; // No error means password is valid
};

/**
 * Validate name format - FLEXIBLE
 * Users can use any name format
 */
const validateName = (name) => {
  if (!name || typeof name !== 'string') return false;
  
  const trimmed = name.trim();
  
  // Basic check: name should have at least 1 character and not be too long
  if (trimmed.length < 1 || trimmed.length > 100) return false;
  
  return true; // Allow ANY characters in name (letters, numbers, symbols, emojis, etc.)
};

/**
 * Sanitize and normalize email
 */
const normalizeEmail = (email) => {
  if (!email) return '';
  return email.trim().toLowerCase();
};

module.exports = {
  validateEmail,
  validatePhoneNumber,
  sanitizeInput,
  validatePasswordStrength,
  validateName,
  normalizeEmail
};