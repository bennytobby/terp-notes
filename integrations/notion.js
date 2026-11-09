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
            const token = typeof integrationToken === 'string'
                ? integrationToken
                : integrationToken?.accessToken;
            if (!token) {
                throw new Error('No Notion access token provided');
            }
            this.client = new Client({ auth: token });
            await this.client.users.me();
            this.isAuthenticated = true;
            return { success: true };
        } catch (error) {
            console.error('Notion authentication failed:', error);
            return {
                success: false,
                error: error.message || 'Invalid Notion integration token. Please check your token and try again.'
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
                filter: { property: 'object', value: 'database' },
                page_size: 50
            });
            const pages = await this.client.search({
                filter: { property: 'object', value: 'page' },
                page_size: 50
            });

            const databaseItems = (databases.results || []).map(db => ({
                id: `database:${db.id}`,
                title: `${db.title?.[0]?.plain_text || 'Untitled'} (database)`,
                url: db.url,
                created_time: db.created_time,
                last_edited_time: db.last_edited_time
            }));
            const pageItems = (pages.results || []).map(page => ({
                id: `page:${page.id}`,
                title: `${this.extractTitle(page)} (page)`,
                url: page.url,
                created_time: page.created_time,
                last_edited_time: page.last_edited_time
            }));

            return {
                success: true,
                databases: [...databaseItems, ...pageItems]
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
        if (page.properties) {
            for (const property of Object.values(page.properties)) {
                if (property?.type === 'title' && property.title?.[0]?.plain_text) {
                    return property.title[0].plain_text;
                }
            }
        }
        return page.title?.[0]?.plain_text || 'Untitled';
    }

    async importSinglePage(pageId) {
        const page = await this.client.pages.retrieve({ page_id: pageId });
        const pageContent = await this.client.blocks.children.list({ block_id: pageId });
        const markdown = this.convertBlocksToMarkdown(pageContent.results);
        return {
            filename: `${this.extractTitle(page)}.md`,
            content: Buffer.from(markdown, 'utf8'),
            metadata: {
                notionPageId: page.id,
                notionUrl: page.url,
                lastEdited: page.last_edited_time,
                created: page.created_time,
                source: 'notion'
            }
        };
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

            const databases = workspacesResult.databases || [];
            return {
                success: true,
                data: {
                    databases,
                    sources: databases.map(db => ({ id: db.id, name: db.title })),
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

            if (sourceId.startsWith('page:')) {
                const file = await this.importSinglePage(sourceId.slice('page:'.length));
                return { success: true, count: 1, files: [file] };
            }

            const databaseId = sourceId.startsWith('database:')
                ? sourceId.slice('database:'.length)
                : sourceId;
            const result = await this.importFromDatabase(databaseId, options);
            if (!result.success) {
                return result;
            }
            return {
                success: true,
                count: result.count || 0,
                files: result.files || []
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
            const databaseId = (options.databaseId || options.targetId || '').replace(/^database:/, '');
            const result = await this.exportToDatabase(fileData, databaseId);
            return {
                success: true,
                pageId: result.notionPageId,
                url: result.notionUrl
            };
        } catch (error) {
            console.error('Error exporting to Notion:', error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = NotionIntegration;
