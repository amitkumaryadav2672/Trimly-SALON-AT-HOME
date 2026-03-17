// auditLogger.js
const fs = require('fs');
const path = require('path');

/**
 * Audit logging utility for security events
 */
class AuditLogger {
  constructor() {
    this.logsDir = path.join(process.cwd(), 'logs');
    
    // Create logs directory if it doesn't exist
    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true });
    }
  }

  /**
   * Log an audit event
   */
  async log(level, action, message, data) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      action,
      message,
      data: data || {}
    };

    try {
      // Console log in development
      if (process.env.NODE_ENV === 'development') {
        console.log(`[${level}] ${action}: ${message}`, data);
      }

      // File log in production
      if (process.env.NODE_ENV === 'production') {
        const date = new Date().toISOString().split('T')[0];
        const logFile = path.join(this.logsDir, `audit_${date}.log`);
        
        fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
      }

      // Send to external service if configured
      if (process.env.AUDIT_LOG_URL) {
        this._sendToExternalService(entry);
      }
    } catch (error) {
      console.error('[AUDIT ERROR]', error.message);
    }
  }

  /**
   * Log authentication event
   */
  async logAuthentication(action, message, data) {
    await this.log('AUTHENTICATION', action, message, data);
  }

  /**
   * Log authorization event
   */
  async logAuthorization(action, message, data) {
    await this.log('AUTHORIZATION', action, message, data);
  }

  /**
   * Log data modification event
   */
  async logDataModification(action, message, data) {
    await this.log('DATA_MODIFICATION', action, message, data);
  }

  /**
   * Log security event
   */
  async logSecurityEvent(action, message, data) {
    await this.log('SECURITY', action, message, data);
  }

  /**
   * Send log to external service
   */
  _sendToExternalService(entry) {
    // Non-blocking async operation
    setImmediate(async () => {
      try {
        await fetch(process.env.AUDIT_LOG_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(entry),
          timeout: 5000
        });
      } catch (error) {
        console.error('[AUDIT LOG SEND ERROR]', error.message);
      }
    });
  }
}

// Create and export a single instance
const auditLogger = new AuditLogger();
module.exports = { auditLogger };