// src/utils/helper.js

/**
 * Converts an expiry string into milliseconds.
 * 
 * Supported formats:
 *   - "15m" → 15 minutes
 *   - "2h"  → 2 hours
 *   - "1d"  → 1 day
 *   - "30s" → 30 seconds
 */
function getMillisecondsFromExpiry(expiry) {
    const unit  = expiry.slice(-1).toLowerCase();
    const value = parseInt(expiry.slice(0, -1), 10);
  
    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default:  return 0;
    }
  }
  
  module.exports = { getMillisecondsFromExpiry };
  