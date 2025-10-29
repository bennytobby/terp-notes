const axios = require('axios');

class OneNoteIntegration {
    constructor() {
        this.accessToken = null;
        this.isAuthenticated = false;
        this.baseUrl = 'https://graph.microsoft.com/v1.0';
    }

    /**
     * Initialize OneNote client with user's access token
     * @param {string} accessToken - User's Microsoft Graph access token
     */
    async initialize(accessToken) {
        try {
            this.accessToken = accessToken;

            // Test the connection by getting user info
            const response = await axios.get(`${this.baseUrl}/me`, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            });

            this.isAuthenticated = true;
            return {
                success: true,
                user: response.data
            };
        } catch (error) {
            console.error('OneNote authentication failed:', error);
            return {
                success: false,
                error: 'Invalid Microsoft Graph access token. Please re-authenticate.'
            };
        }
    }

    /**
     * Get user's OneNote notebooks
     */
    async getNotebooks() {
        if (!this.isAuthenticated) {
            throw new Error('OneNote client not authenticated');
        }

        try {
            const response = await axios.get(`${this.baseUrl}/me/onenote/notebooks`, {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Content-Type': 'application/json'
                }
            });

            return {
                success: true,
                notebooks: response.data.value.map(notebook => ({
                    id: notebook.id,
                    displayName: notebook.displayName,
                    createdDateTime: notebook.createdDateTime,
                    lastModifiedDateTime: notebook.lastModifiedDateTime,
                    isDefault: notebook.isDefault
                }))
            };
        } catch (error) {
            console.error('Error fetching OneNote notebooks:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get sections from a specific notebook
     * @param {string} notebookId - OneNote notebook ID
     */
    async getSections(notebookId) {
        if (!this.isAuthenticated) {
            throw new Error('OneNote client not authenticated');
        }

        try {
            const response = await axios.get(`${this.baseUrl}/me/onenote/notebooks/${notebookId}/sections`, {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Content-Type': 'application/json'
                }
            });

            return {
                success: true,
                sections: response.data.value.map(section => ({
                    id: section.id,
                    displayName: section.displayName,
                    createdDateTime: section.createdDateTime,
                    lastModifiedDateTime: section.lastModifiedDateTime
                }))
            };
        } catch (error) {
            console.error('Error fetching OneNote sections:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Import pages from a OneNote section
     * @param {string} sectionId - OneNote section ID
     * @param {Object} options - Import options
     */
    async importFromSection(sectionId, options = {}) {
        if (!this.isAuthenticated) {
            throw new Error('OneNote client not authenticated');
        }

        try {
            const response = await axios.get(`${this.baseUrl}/me/onenote/sections/${sectionId}/pages`, {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Content-Type': 'application/json'
                }
            });

            const importedFiles = [];

            for (const page of response.data.value) {
                try {
                    // Get page content
                    const contentResponse = await axios.get(`${this.baseUrl}/me/onenote/pages/${page.id}/content`, {
                        headers: {
                            'Authorization': `Bearer ${this.accessToken}`,
                            'Content-Type': 'application/json'
                        }
                    });

                    // Convert OneNote HTML to markdown
                    const markdown = this.convertHtmlToMarkdown(contentResponse.data);

                    // Create file metadata
                    const fileName = page.title + '.md';
                    const fileContent = Buffer.from(markdown, 'utf8');

                    importedFiles.push({
                        filename: fileName,
                        content: fileContent,
                        metadata: {
                            oneNotePageId: page.id,
                            oneNoteUrl: page.links?.oneNoteWebUrl?.href,
                            lastModified: page.lastModifiedDateTime,
                            created: page.createdDateTime,
                            source: 'onenote'
                        }
                    });
                } catch (pageError) {
                    console.error(`Error processing OneNote page ${page.id}:`, pageError);
                }
            }

            return {
                success: true,
                files: importedFiles,
                count: importedFiles.length
            };
        } catch (error) {
            console.error('Error importing from OneNote section:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Export file to OneNote section
     * @param {Object} fileData - File data from Terp Notes
     * @param {string} sectionId - Target OneNote section ID
     */
    async exportToSection(fileData, sectionId) {
        if (!this.isAuthenticated) {
            throw new Error('OneNote client not authenticated');
        }

        try {
            // Convert markdown to OneNote HTML
            const html = this.convertMarkdownToHtml(fileData.content);

            // Create page in OneNote section
            const response = await axios.post(`${this.baseUrl}/me/onenote/sections/${sectionId}/pages`,
                html,
                {
                    headers: {
                        'Authorization': `Bearer ${this.accessToken}`,
                        'Content-Type': 'text/html'
                    }
                }
            );

            return {
                success: true,
                oneNotePageId: response.data.id,
                oneNoteUrl: response.data.links?.oneNoteWebUrl?.href
            };
        } catch (error) {
            console.error('Error exporting to OneNote:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Convert OneNote HTML to markdown
     * @param {string} html - OneNote HTML content
     */
    convertHtmlToMarkdown(html) {
        // This is a simplified conversion - you might want to use a library like turndown
        let markdown = html
            .replace(/<h1[^>]*>(.*?)<\/h1>/gi, '# $1\n\n')
            .replace(/<h2[^>]*>(.*?)<\/h2>/gi, '## $1\n\n')
            .replace(/<h3[^>]*>(.*?)<\/h3>/gi, '### $1\n\n')
            .replace(/<h4[^>]*>(.*?)<\/h4>/gi, '#### $1\n\n')
            .replace(/<h5[^>]*>(.*?)<\/h5>/gi, '##### $1\n\n')
            .replace(/<h6[^>]*>(.*?)<\/h6>/gi, '###### $1\n\n')
            .replace(/<strong[^>]*>(.*?)<\/strong>/gi, '**$1**')
            .replace(/<b[^>]*>(.*?)<\/b>/gi, '**$1**')
            .replace(/<em[^>]*>(.*?)<\/em>/gi, '*$1*')
            .replace(/<i[^>]*>(.*?)<\/i>/gi, '*$1*')
            .replace(/<u[^>]*>(.*?)<\/u>/gi, '<u>$1</u>')
            .replace(/<s[^>]*>(.*?)<\/s>/gi, '~~$1~~')
            .replace(/<strike[^>]*>(.*?)<\/strike>/gi, '~~$1~~')
            .replace(/<ul[^>]*>(.*?)<\/ul>/gis, (match, content) => {
                const items = content.match(/<li[^>]*>(.*?)<\/li>/gis);
                if (items) {
                    return items.map(item =>
                        '- ' + item.replace(/<li[^>]*>(.*?)<\/li>/i, '$1').trim()
                    ).join('\n') + '\n\n';
                }
                return match;
            })
            .replace(/<ol[^>]*>(.*?)<\/ol>/gis, (match, content) => {
                const items = content.match(/<li[^>]*>(.*?)<\/li>/gis);
                if (items) {
                    return items.map((item, index) =>
                        `${index + 1}. ` + item.replace(/<li[^>]*>(.*?)<\/li>/i, '$1').trim()
                    ).join('\n') + '\n\n';
                }
                return match;
            })
            .replace(/<blockquote[^>]*>(.*?)<\/blockquote>/gis, '> $1\n\n')
            .replace(/<code[^>]*>(.*?)<\/code>/gi, '`$1`')
            .replace(/<pre[^>]*>(.*?)<\/pre>/gis, '```\n$1\n```\n\n')
            .replace(/<a[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)')
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<p[^>]*>(.*?)<\/p>/gi, '$1\n\n')
            .replace(/<div[^>]*>(.*?)<\/div>/gi, '$1\n')
            .replace(/<[^>]+>/g, '') // Remove remaining HTML tags
            .replace(/\n\s*\n\s*\n/g, '\n\n') // Clean up multiple newlines
            .trim();

        return markdown;
    }

    /**
     * Convert markdown to OneNote HTML
     * @param {string} markdown - Markdown content
     */
    convertMarkdownToHtml(markdown) {
        // This is a simplified conversion - you might want to use a library like marked
        let html = markdown
            .replace(/^# (.*$)/gim, '<h1>$1</h1>')
            .replace(/^## (.*$)/gim, '<h2>$1</h2>')
            .replace(/^### (.*$)/gim, '<h3>$1</h3>')
            .replace(/^#### (.*$)/gim, '<h4>$1</h4>')
            .replace(/^##### (.*$)/gim, '<h5>$1</h5>')
            .replace(/^###### (.*$)/gim, '<h6>$1</h6>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/~~(.*?)~~/g, '<s>$1</s>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/```([\s\S]*?)```/g, '<pre>$1</pre>')
            .replace(/^> (.*$)/gim, '<blockquote>$1</blockquote>')
            .replace(/^\- (.*$)/gim, '<ul><li>$1</li></ul>')
            .replace(/^\d+\. (.*$)/gim, '<ol><li>$1</li></ol>')
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
            .replace(/\n/g, '<br>');

        return `<html><body>${html}</body></html>`;
    }

    /**
     * Get integration data (required by server)
     * @param {Object} credentials - Integration credentials
     */
    async getData(credentials) {
        try {
            // Initialize with credentials
            const initResult = await this.initialize(credentials.accessToken);
            if (!initResult.success) {
                return { success: false, error: initResult.error };
            }

            // Get user's notebooks
            const notebooksResult = await this.getNotebooks();
            if (!notebooksResult.success) {
                return { success: false, error: notebooksResult.error };
            }

            return {
                success: true,
                data: {
                    notebooks: notebooksResult.notebooks,
                    integrationType: 'onenote',
                    connected: true
                }
            };
        } catch (error) {
            console.error('Error getting OneNote data:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Import from OneNote (wrapper method for server)
     * @param {string} sourceId - Section ID to import from
     * @param {Object} credentials - Integration credentials
     * @param {Object} options - Import options
     */
    async import(sourceId, credentials, options = {}) {
        try {
            // Initialize with credentials
            const initResult = await this.initialize(credentials.accessToken);
            if (!initResult.success) {
                return { success: false, error: initResult.error };
            }

            // Import from the section
            const result = await this.importFromSection(sourceId, options);
            return {
                success: true,
                count: result.count || 0,
                files: result.files || []
            };
        } catch (error) {
            console.error('Error importing from OneNote:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Export to OneNote (wrapper method for server)
     * @param {Object} fileData - Data to export
     * @param {Object} credentials - Integration credentials
     * @param {Object} options - Export options
     */
    async export(fileData, credentials, options = {}) {
        try {
            // Initialize with credentials
            const initResult = await this.initialize(credentials.accessToken);
            if (!initResult.success) {
                return { success: false, error: initResult.error };
            }

            // Export to the section
            const result = await this.exportToSection(fileData, options.sectionId);
            return {
                success: true,
                pageId: result.oneNotePageId,
                url: result.oneNoteUrl
            };
        } catch (error) {
            console.error('Error exporting to OneNote:', error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = OneNoteIntegration;
