const crypto = require('crypto');

class UserIntegrationsModel {
    constructor(db, collectionName = 'user_integrations') {
        this.db = db;
        this.collection = collectionName;
        this.encryptionKey = process.env.INTEGRATION_ENCRYPTION_KEY || 'default-encryption-key-change-in-production';
    }

    /**
     * Encrypt sensitive data
     * @param {string} text - Text to encrypt
     */
    encrypt(text) {
        const iv = crypto.randomBytes(16);
        // Create a 32-byte key from the encryption key string
        const key = crypto.createHash('sha256').update(this.encryptionKey).digest();
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }

    /**
     * Decrypt sensitive data
     * @param {string} encryptedText - Encrypted text
     */
    decrypt(encryptedText) {
        try {
            const textParts = encryptedText.split(':');
            const iv = Buffer.from(textParts.shift(), 'hex');
            const encryptedData = textParts.join(':');
            // Create a 32-byte key from the encryption key string
            const key = crypto.createHash('sha256').update(this.encryptionKey).digest();
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            console.error('Decryption error:', error);
            return null;
        }
    }

    /**
     * Save user integration credentials
     * @param {string} userId - User ID
     * @param {string} integrationId - Integration ID (google, microsoft, notion, obsidian)
     * @param {Object} credentials - Integration credentials
     */
    async saveIntegration(userId, integrationId, credentials) {
        try {
            const encryptedCredentials = {
                accessToken: credentials.accessToken ? this.encrypt(credentials.accessToken) : null,
                refreshToken: credentials.refreshToken ? this.encrypt(credentials.refreshToken) : null,
                expiresAt: credentials.expiresAt || null,
                tokenType: credentials.tokenType || 'Bearer',
                scope: credentials.scope || null,
                // For Obsidian, store the vault path (not encrypted)
                vaultPath: credentials.vaultPath || null,
                // Metadata
                connectedAt: new Date(),
                lastUsedAt: new Date(),
                isActive: true
            };

            await this.db.collection(this.collection).updateOne(
                { userId: userId, integrationId: integrationId },
                {
                    $set: encryptedCredentials,
                    $setOnInsert: { userId: userId, integrationId: integrationId }
                },
                { upsert: true }
            );

            return { success: true };
        } catch (error) {
            console.error('Error saving integration:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get user integration credentials
     * @param {string} userId - User ID
     * @param {string} integrationId - Integration ID
     */
    async getIntegration(userId, integrationId) {
        try {
            const result = await this.db.collection(this.collection).findOne({
                userId: userId,
                integrationId: integrationId,
                isActive: true
            });

            if (!result) {
                return { success: false, error: 'Integration not found' };
            }

            // Decrypt sensitive data
            const decryptedCredentials = {
                accessToken: result.accessToken ? this.decrypt(result.accessToken) : null,
                refreshToken: result.refreshToken ? this.decrypt(result.refreshToken) : null,
                expiresAt: result.expiresAt,
                tokenType: result.tokenType,
                scope: result.scope,
                vaultPath: result.vaultPath,
                connectedAt: result.connectedAt,
                lastUsedAt: result.lastUsedAt
            };

            return { success: true, credentials: decryptedCredentials };
        } catch (error) {
            console.error('Error getting integration:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get all user integrations
     * @param {string} userId - User ID
     */
    async getUserIntegrations(userId) {
        try {
            const integrations = await this.db.collection(this.collection).find({
                userId: userId,
                isActive: true
            }).toArray();

            const result = integrations.map(integration => ({
                integrationId: integration.integrationId,
                connectedAt: integration.connectedAt,
                lastUsedAt: integration.lastUsedAt,
                isActive: integration.isActive,
                // Don't return sensitive data in list
                hasCredentials: !!(integration.accessToken || integration.vaultPath)
            }));

            return { success: true, integrations: result };
        } catch (error) {
            console.error('Error getting user integrations:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Update integration last used timestamp
     * @param {string} userId - User ID
     * @param {string} integrationId - Integration ID
     */
    async updateLastUsed(userId, integrationId) {
        try {
            await this.db.collection(this.collection).updateOne(
                { userId: userId, integrationId: integrationId },
                { $set: { lastUsedAt: new Date() } }
            );
            return { success: true };
        } catch (error) {
            console.error('Error updating last used:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Update integration credentials (for token refresh)
     * @param {string} userId - User ID
     * @param {string} integrationId - Integration ID
     * @param {Object} newCredentials - New credentials
     */
    async updateCredentials(userId, integrationId, newCredentials) {
        try {
            const updateData = {};

            if (newCredentials.accessToken) {
                updateData.accessToken = this.encrypt(newCredentials.accessToken);
            }
            if (newCredentials.refreshToken) {
                updateData.refreshToken = this.encrypt(newCredentials.refreshToken);
            }
            if (newCredentials.expiresAt) {
                updateData.expiresAt = newCredentials.expiresAt;
            }
            if (newCredentials.scope) {
                updateData.scope = newCredentials.scope;
            }

            updateData.lastUsedAt = new Date();

            await this.db.collection(this.collection).updateOne(
                { userId: userId, integrationId: integrationId },
                { $set: updateData }
            );

            return { success: true };
        } catch (error) {
            console.error('Error updating credentials:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Disconnect user integration
     * @param {string} userId - User ID
     * @param {string} integrationId - Integration ID
     */
    async disconnectIntegration(userId, integrationId) {
        try {
            await this.db.collection(this.collection).updateOne(
                { userId: userId, integrationId: integrationId },
                {
                    $set: {
                        isActive: false,
                        disconnectedAt: new Date()
                    }
                }
            );
            return { success: true };
        } catch (error) {
            console.error('Error disconnecting integration:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Delete user integration (alias for disconnectIntegration for backward compatibility)
     * @param {string} userId - User ID
     * @param {string} integrationId - Integration ID
     */
    async deleteIntegration(userId, integrationId) {
        return this.disconnectIntegration(userId, integrationId);
    }

    /**
     * Check if integration credentials are expired
     * @param {Object} credentials - Integration credentials
     */
    isExpired(credentials) {
        if (!credentials.expiresAt) {
            return false; // No expiration set
        }
        return new Date() > new Date(credentials.expiresAt);
    }

    /**
     * Clean up expired integrations (run periodically)
     */
    async cleanupExpiredIntegrations() {
        try {
            const result = await this.db.collection(this.collection).updateMany(
                {
                    isActive: true,
                    expiresAt: { $lt: new Date() }
                },
                {
                    $set: {
                        isActive: false,
                        expiredAt: new Date()
                    }
                }
            );

            return {
                success: true,
                updatedCount: result.modifiedCount
            };
        } catch (error) {
            console.error('Error cleaning up expired integrations:', error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = UserIntegrationsModel;
