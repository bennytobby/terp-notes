/**
 * Password Validation Utility
 * Enforces strong password requirements
 */

const PASSWORD_REQUIREMENTS = {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumber: true,
    requireSpecial: true,
    specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {object} - { isValid: boolean, errors: string[] }
 */
function validatePassword(password) {
    const errors = [];

    // Check if password exists
    if (!password) {
        errors.push('Password is required');
        return { isValid: false, errors };
    }

    // Length check
    if (password.length < PASSWORD_REQUIREMENTS.minLength) {
        errors.push(`Password must be at least ${PASSWORD_REQUIREMENTS.minLength} characters long`);
    }

    if (password.length > PASSWORD_REQUIREMENTS.maxLength) {
        errors.push(`Password must be less than ${PASSWORD_REQUIREMENTS.maxLength} characters long`);
    }

    // Uppercase check
    if (PASSWORD_REQUIREMENTS.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter (A-Z)');
    }

    // Lowercase check
    if (PASSWORD_REQUIREMENTS.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter (a-z)');
    }

    // Number check
    if (PASSWORD_REQUIREMENTS.requireNumber && !/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number (0-9)');
    }

    // Special character check
    if (PASSWORD_REQUIREMENTS.requireSpecial) {
        const specialCharsRegex = new RegExp(`[${PASSWORD_REQUIREMENTS.specialChars.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]`);
        if (!specialCharsRegex.test(password)) {
            errors.push(`Password must contain at least one special character (${PASSWORD_REQUIREMENTS.specialChars})`);
        }
    }

    // Common password check (basic)
    const commonPasswords = [
        'password', 'password123', '12345678', 'qwerty', 'abc123', 
        'Password1', 'Password123', 'welcome', 'monkey', 'dragon',
        'master', 'sunshine', 'princess', 'letmein', 'admin'
    ];
    
    if (commonPasswords.includes(password.toLowerCase())) {
        errors.push('This password is too common. Please choose a more unique password');
    }

    return {
        isValid: errors.length === 0,
        errors
    };
}

/**
 * Get password requirements as user-friendly list
 * @returns {string[]} - Array of requirement strings
 */
function getPasswordRequirements() {
    const requirements = [];
    
    requirements.push(`At least ${PASSWORD_REQUIREMENTS.minLength} characters long`);
    
    if (PASSWORD_REQUIREMENTS.requireUppercase) {
        requirements.push('At least one uppercase letter (A-Z)');
    }
    
    if (PASSWORD_REQUIREMENTS.requireLowercase) {
        requirements.push('At least one lowercase letter (a-z)');
    }
    
    if (PASSWORD_REQUIREMENTS.requireNumber) {
        requirements.push('At least one number (0-9)');
    }
    
    if (PASSWORD_REQUIREMENTS.requireSpecial) {
        requirements.push(`At least one special character (${PASSWORD_REQUIREMENTS.specialChars})`);
    }
    
    return requirements;
}

/**
 * Check password strength level (for UI feedback)
 * @param {string} password - Password to check
 * @returns {object} - { strength: 'weak'|'medium'|'strong', score: 0-100 }
 */
function checkPasswordStrength(password) {
    if (!password) {
        return { strength: 'weak', score: 0 };
    }

    let score = 0;

    // Length score (0-30 points)
    if (password.length >= 8) score += 10;
    if (password.length >= 12) score += 10;
    if (password.length >= 16) score += 10;

    // Character variety (0-40 points)
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^a-zA-Z0-9]/.test(password)) score += 10;

    // Complexity patterns (0-30 points)
    const hasMultipleNumbers = (password.match(/[0-9]/g) || []).length >= 2;
    const hasMultipleSpecial = (password.match(/[^a-zA-Z0-9]/g) || []).length >= 2;
    const hasNoSequential = !/(.)\1{2,}/.test(password); // No 3+ repeated chars
    
    if (hasMultipleNumbers) score += 10;
    if (hasMultipleSpecial) score += 10;
    if (hasNoSequential) score += 10;

    // Determine strength
    let strength = 'weak';
    if (score >= 70) strength = 'strong';
    else if (score >= 40) strength = 'medium';

    return { strength, score };
}

module.exports = {
    validatePassword,
    getPasswordRequirements,
    checkPasswordStrength,
    PASSWORD_REQUIREMENTS
};

