const { Client } = require('@notionhq/client');

class NotionIntegration {
    constructor() {
        this.client = null;
        this.isAuthenticated = false;
    }

    /**
     * Initialize Notion client with user's integration token
     * @param {string} integrationToken - User's Notion integration token
     */
    async initialize(integrationToken) {
        try {
            this.client = new Client({ auth: integrationToken });
            // Test the connection
            await this.client.users.me();
            this.isAuthenticated = true;
            return { success: true };
        } catch (error) {
            console.error('Notion authentication failed:', error);
            return {
                success: false,
                error: 'Invalid Notion integration token. Please check your token and try again.'
            };
        }
    }

    /**
     * Get user's Notion workspaces and databases
     */
    async getWorkspaces() {
        if (!this.isAuthenticated) {
            throw new Error('Notion client not authenticated');
        }

        try {
            const databases = await this.client.search({
                filter: {
                    property: 'object',
                    value: 'database'
                }
            });

            return {
                success: true,
                databases: databases.results.map(db => ({
                    id: db.id,
                    title: db.title[0]?.plain_text || 'Untitled',
                    url: db.url,
                    created_time: db.created_time,
                    last_edited_time: db.last_edited_time
                }))
            };
        } catch (error) {
            console.error('Error fetching Notion workspaces:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Import pages from a Notion database
     * @param {string} databaseId - Notion database ID
     * @param {Object} options - Import options
     */
    async importFromDatabase(databaseId, options = {}) {
        if (!this.isAuthenticated) {
            throw new Error('Notion client not authenticated');
        }

        try {
            const pages = await this.client.databases.query({
                database_id: databaseId,
                page_size: options.limit || 100
            });

            const importedFiles = [];

            for (const page of pages.results) {
                try {
                    // Get page content
                    const pageContent = await this.client.blocks.children.list({
                        block_id: page.id
                    });

                    // Convert Notion blocks to markdown
                    const markdown = this.convertBlocksToMarkdown(pageContent.results);

                    // Create file metadata
                    const fileName = this.extractTitle(page) + '.md';
                    const fileContent = Buffer.from(markdown, 'utf8');

                    importedFiles.push({
                        filename: fileName,
                        content: fileContent,
                        metadata: {
                            notionPageId: page.id,
                            notionUrl: page.url,
                            lastEdited: page.last_edited_time,
                            created: page.created_time,
                            source: 'notion'
                        }
                    });
                } catch (pageError) {
                    console.error(`Error processing page ${page.id}:`, pageError);
                }
            }

            return {
                success: true,
                files: importedFiles,
                count: importedFiles.length
            };
        } catch (error) {
            console.error('Error importing from Notion database:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Export file to Notion database
     * @param {Object} fileData - File data from Terp Notes
     * @param {string} databaseId - Target Notion database ID
     */
    async exportToDatabase(fileData, databaseId) {
        if (!this.isAuthenticated) {
            throw new Error('Notion client not authenticated');
        }

        try {
            // Convert file content to Notion blocks
            const blocks = this.convertMarkdownToBlocks(fileData.content);

            // Create page in Notion database
            const response = await this.client.pages.create({
                parent: { database_id: databaseId },
                properties: {
                    title: {
                        title: [
                            {
                                text: {
                                    content: fileData.originalName || fileData.filename
                                }
                            }
                        ]
                    }
                },
                children: blocks
            });

            return {
                success: true,
                notionPageId: response.id,
                notionUrl: response.url
            };
        } catch (error) {
            console.error('Error exporting to Notion:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Convert Notion blocks to markdown
     * @param {Array} blocks - Notion blocks
     */
    convertBlocksToMarkdown(blocks) {
        let markdown = '';

        for (const block of blocks) {
            switch (block.type) {
                case 'paragraph':
                    markdown += this.convertRichText(block.paragraph.rich_text) + '\n\n';
                    break;
                case 'heading_1':
                    markdown += '# ' + this.convertRichText(block.heading_1.rich_text) + '\n\n';
                    break;
                case 'heading_2':
                    markdown += '## ' + this.convertRichText(block.heading_2.rich_text) + '\n\n';
                    break;
                case 'heading_3':
                    markdown += '### ' + this.convertRichText(block.heading_3.rich_text) + '\n\n';
                    break;
                case 'bulleted_list_item':
                    markdown += '- ' + this.convertRichText(block.bulleted_list_item.rich_text) + '\n';
                    break;
                case 'numbered_list_item':
                    markdown += '1. ' + this.convertRichText(block.numbered_list_item.rich_text) + '\n';
                    break;
                case 'code':
                    markdown += '```' + (block.code.language || '') + '\n';
                    markdown += this.convertRichText(block.code.rich_text) + '\n';
                    markdown += '```\n\n';
                    break;
                case 'quote':
                    markdown += '> ' + this.convertRichText(block.quote.rich_text) + '\n\n';
                    break;
                default:
                    // Handle other block types as plain text
                    if (block.paragraph) {
                        markdown += this.convertRichText(block.paragraph.rich_text) + '\n\n';
                    }
            }
        }

        return markdown;
    }

    /**
     * Convert Notion rich text to markdown
     * @param {Array} richText - Notion rich text array
     */
    convertRichText(richText) {
        if (!richText || richText.length === 0) return '';

        return richText.map(text => {
            let content = text.plain_text;

            if (text.annotations.bold) content = `**${content}**`;
            if (text.annotations.italic) content = `*${content}*`;
            if (text.annotations.strikethrough) content = `~~${content}~~`;
            if (text.annotations.code) content = `\`${content}\``;

            if (text.href) content = `[${content}](${text.href})`;

            return content;
        }).join('');
    }

    /**
     * Convert markdown to Notion blocks
     * @param {string} markdown - Markdown content
     */
    convertMarkdownToBlocks(markdown) {
        const lines = markdown.split('\n');
        const blocks = [];

        for (const line of lines) {
            if (line.trim() === '') continue;

            if (line.startsWith('# ')) {
                blocks.push({
                    type: 'heading_1',
                    heading_1: {
                        rich_text: [{ type: 'text', text: { content: line.substring(2) } }]
                    }
                });
            } else if (line.startsWith('## ')) {
                blocks.push({
                    type: 'heading_2',
                    heading_2: {
                        rich_text: [{ type: 'text', text: { content: line.substring(3) } }]
                    }
                });
            } else if (line.startsWith('### ')) {
                blocks.push({
                    type: 'heading_3',
                    heading_3: {
                        rich_text: [{ type: 'text', text: { content: line.substring(4) } }]
                    }
                });
            } else if (line.startsWith('- ')) {
                blocks.push({
                    type: 'bulleted_list_item',
                    bulleted_list_item: {
                        rich_text: [{ type: 'text', text: { content: line.substring(2) } }]
                    }
                });
            } else if (line.startsWith('> ')) {
                blocks.push({
                    type: 'quote',
                    quote: {
                        rich_text: [{ type: 'text', text: { content: line.substring(2) } }]
                    }
                });
            } else {
                blocks.push({
                    type: 'paragraph',
                    paragraph: {
                        rich_text: [{ type: 'text', text: { content: line } }]
                    }
                });
            }
        }

        return blocks;
    }

    /**
     * Extract title from Notion page
     * @param {Object} page - Notion page object
     */
    extractTitle(page) {
        const titleProperty = page.properties.title || page.properties.Name;
        if (titleProperty && titleProperty.title && titleProperty.title.length > 0) {
            return titleProperty.title[0].plain_text;
        }
        return 'Untitled';
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

            // Get user's workspaces
            const workspacesResult = await this.getWorkspaces();
            if (!workspacesResult.success) {
                return { success: false, error: workspacesResult.error };
            }

            return {
                success: true,
                data: {
                    databases: workspacesResult.databases,
                    integrationType: 'notion',
                    connected: true
                }
            };
        } catch (error) {
            console.error('Error getting Notion data:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Import from Notion (wrapper method for server)
     * @param {string} sourceId - Database ID to import from
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

            // Import from the database
            const result = await this.importFromDatabase(sourceId, options);
            return {
                success: true,
                count: result.pages ? result.pages.length : 0,
                files: result.pages || []
            };
        } catch (error) {
            console.error('Error importing from Notion:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Export to Notion (wrapper method for server)
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

            // Export to the database
            const result = await this.exportToDatabase(fileData, options.databaseId);
            return {
                success: true,
                pageId: result.pageId,
                url: result.url
            };
        } catch (error) {
            console.error('Error exporting to Notion:', error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = NotionIntegration;
