const fs = require('fs');
const path = require('path');

class ObsidianIntegration {
    constructor() {
        this.vaultPath = null;
        this.isInitialized = false;
    }

    /**
     * Initialize Obsidian integration with vault path
     * @param {string} vaultPath - Path to Obsidian vault
     */
    async initialize(vaultPath) {
        try {
            // Check if vault path exists and contains .obsidian folder
            if (!fs.existsSync(vaultPath)) {
                return {
                    success: false,
                    error: 'Vault path does not exist'
                };
            }

            const obsidianConfigPath = path.join(vaultPath, '.obsidian');
            if (!fs.existsSync(obsidianConfigPath)) {
                return {
                    success: false,
                    error: 'Not a valid Obsidian vault (missing .obsidian folder)'
                };
            }

            this.vaultPath = vaultPath;
            this.isInitialized = true;

            return { success: true };
        } catch (error) {
            console.error('Obsidian vault initialization failed:', error);
            return {
                success: false,
                error: 'Failed to initialize Obsidian vault'
            };
        }
    }

    /**
     * Get vault structure and files
     */
    async getVaultStructure() {
        if (!this.isInitialized) {
            throw new Error('Obsidian vault not initialized');
        }

        try {
            const structure = await this.scanDirectory(this.vaultPath);
            return {
                success: true,
                structure: structure
            };
        } catch (error) {
            console.error('Error scanning Obsidian vault:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Import files from Obsidian vault
     * @param {string} folderPath - Specific folder to import from (optional)
     * @param {Object} options - Import options
     */
    async importFromVault(folderPath = '', options = {}) {
        if (!this.isInitialized) {
            throw new Error('Obsidian vault not initialized');
        }

        try {
            const importPath = folderPath ? path.join(this.vaultPath, folderPath) : this.vaultPath;
            const files = await this.scanDirectory(importPath, { includeContent: true });

            const importedFiles = [];

            for (const file of files) {
                if (file.type === 'file' && file.name.endsWith('.md')) {
                    try {
                        const content = fs.readFileSync(file.fullPath, 'utf8');
                        const processedContent = this.processObsidianContent(content);

                        importedFiles.push({
                            filename: file.name,
                            content: Buffer.from(processedContent, 'utf8'),
                            metadata: {
                                obsidianPath: file.relativePath,
                                obsidianFullPath: file.fullPath,
                                lastModified: file.stats.mtime,
                                created: file.stats.birthtime,
                                source: 'obsidian'
                            }
                        });
                    } catch (fileError) {
                        console.error(`Error processing Obsidian file ${file.name}:`, fileError);
                    }
                }
            }

            return {
                success: true,
                files: importedFiles,
                count: importedFiles.length
            };
        } catch (error) {
            console.error('Error importing from Obsidian vault:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Export file to Obsidian vault
     * @param {Object} fileData - File data from Terp Notes
     * @param {string} targetFolder - Target folder in vault (optional)
     */
    async exportToVault(fileData, targetFolder = '') {
        if (!this.isInitialized) {
            throw new Error('Obsidian vault not initialized');
        }

        try {
            const exportPath = targetFolder ?
                path.join(this.vaultPath, targetFolder) :
                this.vaultPath;

            // Ensure target directory exists
            if (!fs.existsSync(exportPath)) {
                fs.mkdirSync(exportPath, { recursive: true });
            }

            // Process content for Obsidian compatibility
            const processedContent = this.processContentForObsidian(fileData.content);

            // Generate filename
            const fileName = fileData.originalName || fileData.filename;
            const obsidianFileName = fileName.endsWith('.md') ? fileName : fileName + '.md';
            const filePath = path.join(exportPath, obsidianFileName);

            // Write file to vault
            fs.writeFileSync(filePath, processedContent, 'utf8');

            return {
                success: true,
                obsidianPath: path.relative(this.vaultPath, filePath),
                fullPath: filePath
            };
        } catch (error) {
            console.error('Error exporting to Obsidian vault:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Scan directory recursively
     * @param {string} dirPath - Directory path to scan
     * @param {Object} options - Scan options
     */
    async scanDirectory(dirPath, options = {}) {
        const items = [];

        try {
            const entries = fs.readdirSync(dirPath, { withFileTypes: true });

            for (const entry of entries) {
                const fullPath = path.join(dirPath, entry.name);
                const relativePath = path.relative(this.vaultPath, fullPath);

                // Skip .obsidian folder
                if (entry.name === '.obsidian') continue;

                const item = {
                    name: entry.name,
                    type: entry.isDirectory() ? 'folder' : 'file',
                    relativePath: relativePath,
                    fullPath: fullPath
                };

                if (entry.isFile()) {
                    const stats = fs.statSync(fullPath);
                    item.stats = stats;
                    item.size = stats.size;
                }

                if (entry.isDirectory()) {
                    item.children = await this.scanDirectory(fullPath, options);
                }

                items.push(item);
            }
        } catch (error) {
            console.error(`Error scanning directory ${dirPath}:`, error);
        }

        return items;
    }

    /**
     * Process Obsidian content for import
     * @param {string} content - Obsidian markdown content
     */
    processObsidianContent(content) {
        // Convert Obsidian-specific syntax to standard markdown
        let processed = content;

        // Convert wikilinks [[link]] to markdown links [link](link)
        processed = processed.replace(/\[\[([^\]]+)\]\]/g, (match, link) => {
            const [text, alias] = link.split('|');
            const linkText = alias || text;
            const linkPath = text.replace(/\s+/g, '%20'); // URL encode spaces
            return `[${linkText}](${linkPath})`;
        });

        // Convert block references ![[block]] to markdown
        processed = processed.replace(/!\[\[([^\]]+)\]\]/g, (match, block) => {
            return `![${block}](${block})`;
        });

        // Convert tags #tag to markdown
        processed = processed.replace(/#([a-zA-Z0-9_\/]+)/g, '`#$1`');

        // Convert callouts to markdown blockquotes
        processed = processed.replace(/^> \[!([^\]]+)\](.*)$/gm, '> **$1**$2');

        return processed;
    }

    /**
     * Process content for Obsidian compatibility
     * @param {Buffer|string} content - Content to process
     */
    processContentForObsidian(content) {
        let processed = typeof content === 'string' ? content : content.toString('utf8');

        // Convert markdown links to wikilinks where appropriate
        processed = processed.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (match, text, link) => {
            // If it's a relative link, convert to wikilink
            if (!link.startsWith('http') && !link.startsWith('/')) {
                return `[[${link}|${text}]]`;
            }
            return match;
        });

        // Add frontmatter if not present
        if (!processed.startsWith('---')) {
            const frontmatter = `---
created: ${new Date().toISOString()}
source: terp-notes
---

`;
            processed = frontmatter + processed;
        }

        return processed;
    }

    /**
     * Get vault configuration
     */
    async getVaultConfig() {
        if (!this.isInitialized) {
            throw new Error('Obsidian vault not initialized');
        }

        try {
            const configPath = path.join(this.vaultPath, '.obsidian', 'app.json');
            if (fs.existsSync(configPath)) {
                const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
                return {
                    success: true,
                    config: config
                };
            } else {
                return {
                    success: true,
                    config: null
                };
            }
        } catch (error) {
            console.error('Error reading Obsidian config:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get integration data (required by server)
     * @param {Object} credentials - Integration credentials
     */
    async getData(credentials) {
        try {
            // Initialize with credentials
            const initResult = await this.initialize(credentials.vaultPath);
            if (!initResult.success) {
                return { success: false, error: initResult.error };
            }

            // Get vault structure
            const structureResult = await this.getVaultStructure();
            if (!structureResult.success) {
                return { success: false, error: structureResult.error };
            }

            return {
                success: true,
                data: {
                    files: structureResult.files,
                    integrationType: 'obsidian',
                    connected: true
                }
            };
        } catch (error) {
            console.error('Error getting Obsidian data:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Import from Obsidian (wrapper method for server)
     * @param {string} sourceId - Folder path to import from
     * @param {Object} credentials - Integration credentials
     * @param {Object} options - Import options
     */
    async import(sourceId, credentials, options = {}) {
        try {
            // Initialize with credentials
            const initResult = await this.initialize(credentials.vaultPath);
            if (!initResult.success) {
                return { success: false, error: initResult.error };
            }

            // Import from the vault
            const result = await this.importFromVault(sourceId, options);
            return {
                success: true,
                count: result.files ? result.files.length : 0,
                files: result.files || []
            };
        } catch (error) {
            console.error('Error importing from Obsidian:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Export to Obsidian (wrapper method for server)
     * @param {Object} fileData - Data to export
     * @param {Object} credentials - Integration credentials
     * @param {Object} options - Export options
     */
    async export(fileData, credentials, options = {}) {
        try {
            // Initialize with credentials
            const initResult = await this.initialize(credentials.vaultPath);
            if (!initResult.success) {
                return { success: false, error: initResult.error };
            }

            // Export to the vault
            const result = await this.exportToVault(fileData, options.targetFolder || '');
            return {
                success: true,
                filePath: result.filePath,
                url: result.url
            };
        } catch (error) {
            console.error('Error exporting to Obsidian:', error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = ObsidianIntegration;
