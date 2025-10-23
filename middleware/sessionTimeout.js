/**
 * Session Timeout Middleware
 * Automatically logs out users after inactivity
 */

// Timeout configurations (in milliseconds)
const TIMEOUT_CONFIG = {
    INACTIVITY_TIMEOUT: 60 * 60 * 1000,  // 60 minutes of inactivity (increased from 30)
    ABSOLUTE_TIMEOUT: 24 * 60 * 60 * 1000, // 24 hours absolute (even if active)
    REMEMBER_ME_DURATION: 30 * 24 * 60 * 60 * 1000 // 30 days for "Remember Me"
};

/**
 * Session timeout middleware
 * Checks if user session has expired due to inactivity or absolute timeout
 */
function sessionTimeout(req, res, next) {
    // Skip for public routes
    const publicRoutes = ['/', '/login', '/register', '/forgot-password', '/reset-password', '/verify', '/contact', '/terms', '/privacy'];
    const isPublicRoute = publicRoutes.some(route => req.path === route || req.path.startsWith('/reset-password/') || req.path.startsWith('/verify/'));

    // Skip for API routes (they handle their own authentication)
    const isApiRoute = req.path.startsWith('/api/');

    // Skip for download routes to avoid performance impact on file downloads
    const isDownloadRoute = req.path.startsWith('/download/') || req.path.startsWith('/bulk-download');

    if (isPublicRoute || isApiRoute || isDownloadRoute) {
        return next();
    }

    // Skip if no session or not logged in
    if (!req.session || !req.session.user) {
        return next();
    }

    const now = Date.now();
    const session = req.session;

    // Initialize session timestamps if they don't exist
    if (!session.createdAt) {
        session.createdAt = now;
    }
    if (!session.lastActivity) {
        session.lastActivity = now;
    }

    // Check for absolute timeout (24 hours since session creation)
    const sessionAge = now - session.createdAt;
    const maxAge = session.rememberMe ? TIMEOUT_CONFIG.REMEMBER_ME_DURATION : TIMEOUT_CONFIG.ABSOLUTE_TIMEOUT;

    if (sessionAge > maxAge) {
        console.log(`🕐 Session expired (absolute timeout) for user: ${req.session.user?.userid}`);
        return handleSessionExpiry(req, res, 'Your session has expired. Please login again.');
    }

    // Check for inactivity timeout
    const inactivityDuration = now - session.lastActivity;

    if (inactivityDuration > TIMEOUT_CONFIG.INACTIVITY_TIMEOUT) {
        console.log(`🕐 Session expired (inactivity timeout) for user: ${req.session.user?.userid} after ${Math.round(inactivityDuration / 60000)} minutes`);
        return handleSessionExpiry(req, res, 'Your session expired due to inactivity. Please login again.');
    }

    // Session is still valid - update last activity timestamp
    session.lastActivity = now;

    // Log remaining time for debugging (only in development and only every 5 minutes)
    if (process.env.NODE_ENV === 'development' && Math.random() < 0.1) { // Only log 10% of requests
        const remainingMinutes = Math.floor((TIMEOUT_CONFIG.INACTIVITY_TIMEOUT - inactivityDuration) / 60000);
        console.log(`  Session active for ${req.session.user?.userid} - ${remainingMinutes} minutes until timeout`);
    }

    next();
}

/**
 * Handle session expiry
 */
function handleSessionExpiry(req, res, message) {
    // Store the message before destroying session
    const expiredMessage = message;

    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying expired session:', err);
        }
    });

    // Clear session cookie
    res.clearCookie('connect.sid');

    // Check if it's an API request
    if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(401).json({
            error: 'Session expired',
            message: expiredMessage,
            redirect: '/login'
        });
    }

    // For regular requests, redirect to login with message
    return res.redirect(`/login?session_expired=true&message=${encodeURIComponent(expiredMessage)}`);
}

/**
 * Get session timeout configuration
 */
function getTimeoutConfig() {
    return {
        inactivityMinutes: TIMEOUT_CONFIG.INACTIVITY_TIMEOUT / 60000,
        absoluteHours: TIMEOUT_CONFIG.ABSOLUTE_TIMEOUT / (60 * 60000),
        rememberMeDays: TIMEOUT_CONFIG.REMEMBER_ME_DURATION / (24 * 60 * 60000)
    };
}

/**
 * Manually extend session (useful for "Remember Me" functionality)
 */
function extendSession(req) {
    if (req.session) {
        req.session.lastActivity = Date.now();
        req.session.rememberMe = true;
        console.log(`🔐 Session extended (Remember Me) for user: ${req.session.user?.userid}`);
    }
}

module.exports = {
    sessionTimeout,
    getTimeoutConfig,
    extendSession,
    TIMEOUT_CONFIG
};

