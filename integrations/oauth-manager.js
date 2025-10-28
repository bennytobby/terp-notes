const crypto = require('crypto');

class OAuthManager {
    constructor() {
        // These are the OAuth apps that Terp Notes will register with each provider
        // Each user will connect through these apps to their own accounts
        this.oauthConfigs = {
            google: {
                // Terp Notes' Google OAuth app credentials
                clientId: process.env.GOOGLE_CLIENT_ID,
                clientSecret: process.env.GOOGLE_CLIENT_SECRET,
                redirectUri: `${process.env.BASE_URL || 'http://localhost:3000'}/auth/google/callback`,
                scope: 'openid email profile https://www.googleapis.com/auth/drive.file',
                authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
                tokenUrl: 'https://oauth2.googleapis.com/token',
                userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo'
            },
            microsoft: {
                // Terp Notes' Microsoft OAuth app credentials
                clientId: process.env.MICROSOFT_CLIENT_ID,
                clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
                redirectUri: `${process.env.BASE_URL || 'http://localhost:3000'}/auth/microsoft/callback`,
                scope: 'offline_access User.Read Notes.ReadWrite',
                authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                userInfoUrl: 'https://graph.microsoft.com/v1.0/me'
            },
            notion: {
                // Terp Notes' Notion OAuth app credentials
                clientId: process.env.NOTION_CLIENT_ID,
                clientSecret: process.env.NOTION_CLIENT_SECRET,
                redirectUri: `${process.env.BASE_URL || 'http://localhost:3000'}/auth/notion/callback`,
                scope: '', // Notion ignores scope; owner=user is handled in generateAuthUrl
                authUrl: 'https://api.notion.com/v1/oauth/authorize',
                tokenUrl: 'https://api.notion.com/v1/oauth/token',
                userInfoUrl: 'https://api.notion.com/v1/users/me'
            }
        };
    }

    /**
     * Generate OAuth authorization URL
     * @param {string} provider - OAuth provider (google, microsoft, notion)
     * @param {string} userId - User ID for state parameter
     */
    generateAuthUrl(provider, userId) {
        const config = this.oauthConfigs[provider];
        if (!config) {
            throw new Error(`Unsupported OAuth provider: ${provider}`);
        }

        const state = this.generateState(userId);
        const params = new URLSearchParams({
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            response_type: 'code',
            scope: config.scope,
            state: state
        });

        // Add provider-specific parameters
        if (provider === 'google') {
            params.set('access_type', 'offline');
            params.set('prompt', 'consent');
        }
        // For Notion, ensure owner=user is in the authUrl or add it here
        if (provider === 'notion') {
            params.set('owner', 'user');
        }

        return {
            authUrl: `${config.authUrl}?${params.toString()}`,
            state: state
        };
    }

    /**
     * Exchange authorization code for access token
     * @param {string} provider - OAuth provider
     * @param {string} code - Authorization code
     * @param {string} state - State parameter for verification
     */
    async exchangeCodeForToken(provider, code, state) {
        const config = this.oauthConfigs[provider];
        if (!config) {
            throw new Error(`Unsupported OAuth provider: ${provider}`);
        }

        // Verify state parameter
        const userId = this.verifyState(state);
        if (!userId) {
            throw new Error('Invalid state parameter');
        }

        const tokenData = {
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: config.redirectUri
        };

        try {
            let response;
            if (provider === 'notion') {
                // Notion requires JSON format with Basic auth
                response = await fetch(config.tokenUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Basic ' + Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64'),
                        'Notion-Version': '2022-06-28'
                    },
                    body: JSON.stringify({
                        grant_type: 'authorization_code',
                        code: code,
                        redirect_uri: config.redirectUri
                    })
                });
            } else {
                // Standard OAuth2 format for Google and Microsoft
                response = await fetch(config.tokenUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'application/json'
                    },
                    body: new URLSearchParams(tokenData)
                });
            }

            if (!response.ok) {
                throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`);
            }

            const tokens = await response.json();

            return {
                success: true,
                userId: userId,
                accessToken: tokens.access_token,
                refreshToken: tokens.refresh_token,
                expiresIn: tokens.expires_in,
                tokenType: tokens.token_type,
                scope: tokens.scope
            };
        } catch (error) {
            console.error(`OAuth token exchange error for ${provider}:`, error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Refresh access token using refresh token
     * @param {string} provider - OAuth provider
     * @param {string} refreshToken - Refresh token
     */
    async refreshAccessToken(provider, refreshToken) {
        const config = this.oauthConfigs[provider];
        if (!config) {
            throw new Error(`Unsupported OAuth provider: ${provider}`);
        }

        const tokenData = {
            client_id: config.clientId,
            client_secret: config.clientSecret,
            refresh_token: refreshToken,
            grant_type: 'refresh_token'
        };

        try {
            const response = await fetch(config.tokenUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: new URLSearchParams(tokenData)
            });

            if (!response.ok) {
                throw new Error(`Token refresh failed: ${response.status} ${response.statusText}`);
            }

            const tokens = await response.json();

            return {
                success: true,
                accessToken: tokens.access_token,
                refreshToken: tokens.refresh_token || refreshToken, // Keep old refresh token if new one not provided
                expiresIn: tokens.expires_in,
                tokenType: tokens.token_type
            };
        } catch (error) {
            console.error(`OAuth token refresh error for ${provider}:`, error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Generate secure state parameter
     * @param {string} userId - User ID
     */
    generateState(userId) {
        const secret = process.env.OAUTH_STATE_SECRET;
        if (!secret) {
            throw new Error('OAUTH_STATE_SECRET is required');
        }

        const timestamp = Date.now();
        const random = crypto.randomBytes(16).toString('hex');
        const data = `${userId}:${timestamp}:${random}`;
        const signature = crypto.createHmac('sha256', secret)
            .update(data)
            .digest('hex');
        return Buffer.from(`${data}:${signature}`).toString('base64');
    }

    /**
     * Verify and extract user ID from state parameter
     * @param {string} state - State parameter
     */
    verifyState(state) {
        try {
            console.log('Verifying state parameter:', state);
            const decoded = Buffer.from(state, 'base64').toString('utf8');
            console.log('Decoded state:', decoded);

            // Parse the state format: userId:timestamp:random:signature
            const parts = decoded.split(':');
            if (parts.length !== 4) {
                console.log('Invalid state format, expected 4 parts, got:', parts.length);
                return null;
            }

            const [userId, timestamp, random, signature] = parts;
            console.log('State components - userId:', userId, 'timestamp:', timestamp, 'random:', random, 'signature:', signature);

            // Verify signature
            const secret = process.env.OAUTH_STATE_SECRET;
            if (!secret) {
                throw new Error('OAUTH_STATE_SECRET is required');
            }

            const data = `${userId}:${timestamp}:${random}`;
            const expectedSignature = crypto.createHmac('sha256', secret)
                .update(data)
                .digest('hex');
            console.log('Expected signature:', expectedSignature);
            console.log('Actual signature:', signature);

            if (signature !== expectedSignature) {
                console.log('Signature mismatch!');
                return null;
            }

            // Check if state is not too old (1 hour)
            const stateAge = Date.now() - parseInt(timestamp);
            console.log('State age:', stateAge, 'ms');
            if (stateAge > 3600000) { // 1 hour in milliseconds
                console.log('State too old!');
                return null;
            }

            console.log('State verification successful for user:', userId);
            return userId;
        } catch (error) {
            console.error('State verification error:', error);
            return null;
        }
    }

    /**
     * Get OAuth configuration for a provider
     * @param {string} provider - OAuth provider
     */
    getConfig(provider) {
        return this.oauthConfigs[provider];
    }

    /**
     * Get user info from OAuth provider
     * @param {string} provider - OAuth provider
     * @param {string} accessToken - Access token
     */
    async getUserInfo(provider, accessToken) {
        const config = this.oauthConfigs[provider];
        if (!config) {
            throw new Error(`Unsupported OAuth provider: ${provider}`);
        }

        try {
            const headers = {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            };

            // Add Notion-Version header for Notion API calls
            if (provider === 'notion') {
                headers['Notion-Version'] = '2022-06-28';
            }

            const response = await fetch(config.userInfoUrl, { headers });

            if (!response.ok) {
                throw new Error(`Failed to get user info: ${response.status} ${response.statusText}`);
            }

            const userInfo = await response.json();

            // Normalize user info across providers
            return {
                success: true,
                userInfo: {
                    id: userInfo.id || userInfo.sub,
                    email: userInfo.email || userInfo.userPrincipalName, // Microsoft uses camelCase
                    name: userInfo.name || userInfo.displayName, // Microsoft uses camelCase
                    provider: provider,
                    raw: userInfo
                }
            };
        } catch (error) {
            console.error(`Error getting user info from ${provider}:`, error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Check if OAuth is configured for a provider
     * @param {string} provider - OAuth provider
     */
    isConfigured(provider) {
        const config = this.oauthConfigs[provider];
        return !!(config && config.clientId && config.clientSecret);
    }
}

module.exports = OAuthManager;
