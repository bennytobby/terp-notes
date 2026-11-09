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
            if (!credentials?.accessToken) {
                throw new Error('No valid credentials provided');
            }

            const auth = new google.auth.OAuth2(
                process.env.GOOGLE_CLIENT_ID,
                process.env.GOOGLE_CLIENT_SECRET
            );

            auth.setCredentials({
                access_token: credentials.accessToken,
                refresh_token: credentials.refreshToken || undefined
            });

            this.docs = google.docs({ version: 'v1', auth });
            this.drive = google.drive({ version: 'v3', auth });
            this.isAuthenticated = true;

            return { success: true };
        } catch (error) {
            console.error('Google Docs authentication failed:', error);
            return {
                success: false,
                error: error.message || 'Invalid Google OAuth credentials. Please re-authenticate.'
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
                q: "trashed = false and (mimeType = 'application/vnd.google-apps.document' or mimeType = 'application/pdf' or mimeType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')",
                fields: 'files(id,name,mimeType,createdTime,modifiedTime,webViewLink)',
                orderBy: 'modifiedTime desc',
                pageSize: 50,
                spaces: 'drive',
                corpora: 'user'
            });

            const documents = (response.data.files || []).map(doc => ({
                id: doc.id,
                name: doc.name,
                mimeType: doc.mimeType,
                createdTime: doc.createdTime,
                modifiedTime: doc.modifiedTime,
                webViewLink: doc.webViewLink
            }));

            return {
                success: true,
                documents
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
            const meta = await this.drive.files.get({
                fileId: documentId,
                fields: 'id,name,mimeType,webViewLink,modifiedTime,createdTime'
            });
            const mimeType = meta.data.mimeType;
            const baseName = meta.data.name || 'google-note';
            const metadata = {
                googleDocId: documentId,
                googleDocUrl: meta.data.webViewLink || `https://docs.google.com/document/d/${documentId}/edit`,
                lastModified: meta.data.modifiedTime,
                created: meta.data.createdTime,
                source: 'google-docs'
            };

            if (mimeType === 'application/vnd.google-apps.document') {
                try {
                    const exported = await this.drive.files.export(
                        { fileId: documentId, mimeType: 'text/plain' },
                        { responseType: 'arraybuffer' }
                    );
                    return {
                        success: true,
                        file: {
                            filename: `${baseName}.md`,
                            content: Buffer.from(exported.data),
                            metadata
                        }
                    };
                } catch (exportError) {
                    const doc = await this.docs.documents.get({ documentId });
                    const markdown = this.convertGoogleDocToMarkdown(doc.data);
                    return {
                        success: true,
                        file: {
                            filename: `${doc.data.title || baseName}.md`,
                            content: Buffer.from(markdown, 'utf8'),
                            metadata
                        }
                    };
                }
            }

            const downloaded = await this.drive.files.get(
                { fileId: documentId, alt: 'media' },
                { responseType: 'arraybuffer' }
            );
            // Name the file by its real type: names like "Week 1. Intro" contain a dot but no
            // extension, and a Word file saved without .docx was served as Markdown.
            const filename = require('../utils/note-pipeline').withExtension(baseName, mimeType);
            return {
                success: true,
                file: {
                    filename,
                    content: Buffer.from(downloaded.data),
                    metadata
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

            const documents = documentsResult.documents || [];
            return {
                success: true,
                data: {
                    documents,
                    sources: documents.map(doc => ({ id: doc.id, name: doc.name })),
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

            const result = await this.importDocument(sourceId, options);
            if (!result.success || !result.file) {
                return { success: false, error: result.error || 'Failed to import Google document' };
            }
            return {
                success: true,
                count: 1,
                files: [result.file]
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
                documentId: result.googleDocId,
                url: result.googleDocUrl
            };
        } catch (error) {
            console.error('Error exporting to Google Docs:', error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = GoogleDocsIntegration;
