const { google } = require('googleapis');
const fs = require('fs');
const path = require('path');

class GoogleDocsIntegration {
    constructor() {
        this.docs = null;
        this.drive = null;
        this.isAuthenticated = false;
    }

    /**
     * Initialize Google Docs client with user's OAuth credentials
     * @param {Object} credentials - OAuth2 credentials
     */
    async initialize(credentials) {
        try {
            // Check if we have OAuth tokens (from OAuth flow)
            if (credentials.accessToken && credentials.refreshToken) {
                const auth = new google.auth.OAuth2(
                    process.env.GOOGLE_CLIENT_ID,
                    process.env.GOOGLE_CLIENT_SECRET
                    // No redirect URI needed when using existing tokens
                );

                auth.setCredentials({
                    access_token: credentials.accessToken,
                    refresh_token: credentials.refreshToken
                });

                this.docs = google.docs({ version: 'v1', auth });
                this.drive = google.drive({ version: 'v3', auth });

                // Test the connection
                await this.drive.files.list({ pageSize: 1 });
                this.isAuthenticated = true;

                return { success: true };
            }
            // Fallback to manual credentials (for backward compatibility)
            else if (credentials.clientId && credentials.clientSecret) {
                const auth = new google.auth.OAuth2(
                    credentials.clientId,
                    credentials.clientSecret,
                    credentials.redirectUri
                );

                auth.setCredentials({
                    access_token: credentials.accessToken,
                    refresh_token: credentials.refreshToken
                });

                this.docs = google.docs({ version: 'v1', auth });
                this.drive = google.drive({ version: 'v3', auth });

                // Test the connection
                await this.drive.files.list({ pageSize: 1 });
                this.isAuthenticated = true;

                return { success: true };
            } else {
                throw new Error('No valid credentials provided');
            }
        } catch (error) {
            console.error('Google Docs authentication failed:', error);
            return {
                success: false,
                error: 'Invalid Google OAuth credentials. Please re-authenticate.'
            };
        }
    }

    /**
     * Get user's Google Docs
     */
    async getDocuments() {
        if (!this.isAuthenticated) {
            throw new Error('Google Docs client not authenticated');
        }

        try {
            const response = await this.drive.files.list({
                q: "mimeType contains 'application/vnd.google-apps' or mimeType contains 'application/pdf' or mimeType contains 'application/vnd.openxmlformats'",
                fields: 'files(id,name,mimeType,createdTime,modifiedTime,webViewLink)',
                orderBy: 'modifiedTime desc',
                pageSize: 100
            });

            return {
                success: true,
                documents: response.data.files.map(doc => ({
                    id: doc.id,
                    name: doc.name,
                    mimeType: doc.mimeType,
                    createdTime: doc.createdTime,
                    modifiedTime: doc.modifiedTime,
                    webViewLink: doc.webViewLink
                }))
            };
        } catch (error) {
            console.error('Error fetching Google Docs:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Import content from a Google Doc
     * @param {string} documentId - Google Doc ID
     * @param {Object} options - Import options
     */
    async importDocument(documentId, options = {}) {
        if (!this.isAuthenticated) {
            throw new Error('Google Docs client not authenticated');
        }

        try {
            // Get document content
            const doc = await this.docs.documents.get({
                documentId: documentId
            });

            // Convert Google Docs content to markdown
            const markdown = this.convertGoogleDocToMarkdown(doc.data);

            // Create file metadata
            const fileName = doc.data.title + '.md';
            const fileContent = Buffer.from(markdown, 'utf8');

            return {
                success: true,
                file: {
                    filename: fileName,
                    content: fileContent,
                    metadata: {
                        googleDocId: documentId,
                        googleDocUrl: `https://docs.google.com/document/d/${documentId}/edit`,
                        lastModified: doc.data.modifiedTime,
                        created: doc.data.createdTime,
                        source: 'google-docs'
                    }
                }
            };
        } catch (error) {
            console.error('Error importing Google Doc:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Export file to Google Docs
     * @param {Object} fileData - File data from Terp Notes
     * @param {string} title - Document title
     */
    async exportToDocument(fileData, title) {
        if (!this.isAuthenticated) {
            throw new Error('Google Docs client not authenticated');
        }

        try {
            // Create new Google Doc
            const doc = await this.docs.documents.create({
                requestBody: {
                    title: title || fileData.originalName || fileData.filename
                }
            });

            const documentId = doc.data.documentId;

            // Convert markdown to Google Docs format
            const requests = this.convertMarkdownToGoogleDocsRequests(fileData.content);

            // Apply formatting to the document
            if (requests.length > 0) {
                await this.docs.documents.batchUpdate({
                    documentId: documentId,
                    requestBody: {
                        requests: requests
                    }
                });
            }

            return {
                success: true,
                googleDocId: documentId,
                googleDocUrl: `https://docs.google.com/document/d/${documentId}/edit`
            };
        } catch (error) {
            console.error('Error exporting to Google Docs:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Convert Google Docs content to markdown
     * @param {Object} doc - Google Docs document object
     */
    convertGoogleDocToMarkdown(doc) {
        let markdown = '';
        const content = doc.body.content;

        for (const element of content) {
            if (element.paragraph) {
                markdown += this.convertParagraphToMarkdown(element.paragraph) + '\n\n';
            } else if (element.table) {
                markdown += this.convertTableToMarkdown(element.table) + '\n\n';
            }
        }

        return markdown;
    }

    /**
     * Convert Google Docs paragraph to markdown
     * @param {Object} paragraph - Google Docs paragraph object
     */
    convertParagraphToMarkdown(paragraph) {
        let text = '';

        if (paragraph.elements) {
            for (const element of paragraph.elements) {
                if (element.textRun) {
                    text += this.convertTextRunToMarkdown(element.textRun);
                }
            }
        }

        // Apply paragraph-level formatting
        const style = paragraph.paragraphStyle;
        if (style) {
            if (style.namedStyleType === 'HEADING_1') {
                text = '# ' + text;
            } else if (style.namedStyleType === 'HEADING_2') {
                text = '## ' + text;
            } else if (style.namedStyleType === 'HEADING_3') {
                text = '### ' + text;
            } else if (style.namedStyleType === 'HEADING_4') {
                text = '#### ' + text;
            } else if (style.namedStyleType === 'HEADING_5') {
                text = '##### ' + text;
            } else if (style.namedStyleType === 'HEADING_6') {
                text = '###### ' + text;
            }
        }

        return text;
    }

    /**
     * Convert Google Docs text run to markdown
     * @param {Object} textRun - Google Docs text run object
     */
    convertTextRunToMarkdown(textRun) {
        let text = textRun.content;
        const style = textRun.textStyle;

        if (style) {
            if (style.bold) text = `**${text}**`;
            if (style.italic) text = `*${text}*`;
            if (style.strikethrough) text = `~~${text}~~`;
            if (style.underline) text = `<u>${text}</u>`;
            if (style.link && style.link.url) {
                text = `[${text}](${style.link.url})`;
            }
        }

        return text;
    }

    /**
     * Convert Google Docs table to markdown
     * @param {Object} table - Google Docs table object
     */
    convertTableToMarkdown(table) {
        let markdown = '';

        if (table.tableRows) {
            for (let i = 0; i < table.tableRows.length; i++) {
                const row = table.tableRows[i];
                let rowText = '|';

                if (row.tableCells) {
                    for (const cell of row.tableCells) {
                        let cellText = '';
                        if (cell.content) {
                            for (const element of cell.content) {
                                if (element.paragraph) {
                                    cellText += this.convertParagraphToMarkdown(element.paragraph);
                                }
                            }
                        }
                        rowText += ` ${cellText.trim()} |`;
                    }
                }

                markdown += rowText + '\n';

                // Add header separator for first row
                if (i === 0) {
                    const separator = '|' + ' --- |'.repeat(row.tableCells ? row.tableCells.length : 0);
                    markdown += separator + '\n';
                }
            }
        }

        return markdown;
    }

    /**
     * Convert markdown to Google Docs batch update requests
     * @param {string} markdown - Markdown content
     */
    convertMarkdownToGoogleDocsRequests(markdown) {
        const requests = [];
        const lines = markdown.split('\n');
        let currentIndex = 1;

        for (const line of lines) {
            if (line.trim() === '') continue;

            if (line.startsWith('# ')) {
                requests.push({
                    updateParagraphStyle: {
                        range: {
                            startIndex: currentIndex,
                            endIndex: currentIndex + line.length
                        },
                        paragraphStyle: {
                            namedStyleType: 'HEADING_1'
                        },
                        fields: 'namedStyleType'
                    }
                });
            } else if (line.startsWith('## ')) {
                requests.push({
                    updateParagraphStyle: {
                        range: {
                            startIndex: currentIndex,
                            endIndex: currentIndex + line.length
                        },
                        paragraphStyle: {
                            namedStyleType: 'HEADING_2'
                        },
                        fields: 'namedStyleType'
                    }
                });
            } else if (line.startsWith('### ')) {
                requests.push({
                    updateParagraphStyle: {
                        range: {
                            startIndex: currentIndex,
                            endIndex: currentIndex + line.length
                        },
                        paragraphStyle: {
                            namedStyleType: 'HEADING_3'
                        },
                        fields: 'namedStyleType'
                    }
                });
            }

            currentIndex += line.length + 1; // +1 for newline
        }

        return requests;
    }

    /**
     * Get integration data (required by server)
     * @param {Object} credentials - Integration credentials
     */
    async getData(credentials) {
        try {
            // Initialize with credentials
            const initResult = await this.initialize(credentials);
            if (!initResult.success) {
                return { success: false, error: initResult.error };
            }

            // Get user's documents
            const documentsResult = await this.getDocuments();
            if (!documentsResult.success) {
                return { success: false, error: documentsResult.error };
            }

            return {
                success: true,
                data: {
                    documents: documentsResult.documents,
                    integrationType: 'google-docs',
                    connected: true
                }
            };
        } catch (error) {
            console.error('Error getting Google Docs data:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Import from Google Docs (wrapper method for server)
     * @param {string} sourceId - Document ID to import
     * @param {Object} credentials - Integration credentials
     * @param {Object} options - Import options
     */
    async import(sourceId, credentials, options = {}) {
        try {
            // Initialize with credentials
            const initResult = await this.initialize(credentials);
            if (!initResult.success) {
                return { success: false, error: initResult.error };
            }

            // Import the document
            const result = await this.importDocument(sourceId, options);
            return {
                success: true,
                count: 1,
                files: [result]
            };
        } catch (error) {
            console.error('Error importing from Google Docs:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Export to Google Docs (wrapper method for server)
     * @param {Object} fileData - Data to export
     * @param {Object} credentials - Integration credentials
     * @param {Object} options - Export options
     */
    async export(fileData, credentials, options = {}) {
        try {
            // Initialize with credentials
            const initResult = await this.initialize(credentials);
            if (!initResult.success) {
                return { success: false, error: initResult.error };
            }

            // Export the data
            const result = await this.exportToDocument(fileData, options.title || 'Terp Notes Export');
            return {
                success: true,
                documentId: result.documentId,
                url: result.url
            };
        } catch (error) {
            console.error('Error exporting to Google Docs:', error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = GoogleDocsIntegration;
