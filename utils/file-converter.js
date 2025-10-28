const fs = require('fs');
const path = require('path');

/**
 * File format conversion utilities for integration system
 */
class FileConverter {
    constructor() {
        this.supportedFormats = {
            input: ['.md', '.txt', '.html', '.docx', '.pdf'],
            output: ['.md', '.txt', '.html', '.docx', '.pdf']
        };
    }

    /**
     * Convert file content between different formats
     * @param {Buffer|string} content - File content
     * @param {string} fromFormat - Source format (e.g., '.html', '.md')
     * @param {string} toFormat - Target format (e.g., '.md', '.txt')
     * @param {Object} options - Conversion options
     */
    async convert(content, fromFormat, toFormat, options = {}) {
        try {
            // Normalize formats
            fromFormat = this.normalizeFormat(fromFormat);
            toFormat = this.normalizeFormat(toFormat);

            if (fromFormat === toFormat) {
                return { success: true, content: content };
            }

            // Convert content to string if it's a Buffer
            const textContent = Buffer.isBuffer(content) ? content.toString('utf8') : content;

            let convertedContent;

            // HTML to Markdown
            if (fromFormat === '.html' && toFormat === '.md') {
                convertedContent = this.htmlToMarkdown(textContent);
            }
            // Markdown to HTML
            else if (fromFormat === '.md' && toFormat === '.html') {
                convertedContent = this.markdownToHtml(textContent);
            }
            // HTML to Text
            else if (fromFormat === '.html' && toFormat === '.txt') {
                convertedContent = this.htmlToText(textContent);
            }
            // Markdown to Text
            else if (fromFormat === '.md' && toFormat === '.txt') {
                convertedContent = this.markdownToText(textContent);
            }
            // Text to Markdown
            else if (fromFormat === '.txt' && toFormat === '.md') {
                convertedContent = this.textToMarkdown(textContent);
            }
            // Text to HTML
            else if (fromFormat === '.txt' && toFormat === '.html') {
                convertedContent = this.textToHtml(textContent);
            }
            // Unsupported conversion
            else {
                throw new Error(`Conversion from ${fromFormat} to ${toFormat} is not supported`);
            }

            return {
                success: true,
                content: Buffer.from(convertedContent, 'utf8'),
                originalSize: textContent.length,
                convertedSize: convertedContent.length
            };
        } catch (error) {
            console.error('File conversion error:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Convert HTML to Markdown
     * @param {string} html - HTML content
     */
    htmlToMarkdown(html) {
        let markdown = html
            // Headers
            .replace(/<h1[^>]*>(.*?)<\/h1>/gi, '# $1\n\n')
            .replace(/<h2[^>]*>(.*?)<\/h2>/gi, '## $1\n\n')
            .replace(/<h3[^>]*>(.*?)<\/h3>/gi, '### $1\n\n')
            .replace(/<h4[^>]*>(.*?)<\/h4>/gi, '#### $1\n\n')
            .replace(/<h5[^>]*>(.*?)<\/h5>/gi, '##### $1\n\n')
            .replace(/<h6[^>]*>(.*?)<\/h6>/gi, '###### $1\n\n')
            // Bold and italic
            .replace(/<strong[^>]*>(.*?)<\/strong>/gi, '**$1**')
            .replace(/<b[^>]*>(.*?)<\/b>/gi, '**$1**')
            .replace(/<em[^>]*>(.*?)<\/em>/gi, '*$1*')
            .replace(/<i[^>]*>(.*?)<\/i>/gi, '*$1*')
            // Strikethrough
            .replace(/<s[^>]*>(.*?)<\/s>/gi, '~~$1~~')
            .replace(/<strike[^>]*>(.*?)<\/strike>/gi, '~~$1~~')
            // Code
            .replace(/<code[^>]*>(.*?)<\/code>/gi, '`$1`')
            .replace(/<pre[^>]*>(.*?)<\/pre>/gis, '```\n$1\n```\n\n')
            // Links
            .replace(/<a[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)')
            // Images
            .replace(/<img[^>]*src="([^"]*)"[^>]*alt="([^"]*)"[^>]*>/gi, '![$2]($1)')
            .replace(/<img[^>]*alt="([^"]*)"[^>]*src="([^"]*)"[^>]*>/gi, '![$1]($2)')
            // Lists
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
            // Blockquotes
            .replace(/<blockquote[^>]*>(.*?)<\/blockquote>/gis, '> $1\n\n')
            // Line breaks
            .replace(/<br\s*\/?>/gi, '\n')
            // Paragraphs
            .replace(/<p[^>]*>(.*?)<\/p>/gi, '$1\n\n')
            // Divs
            .replace(/<div[^>]*>(.*?)<\/div>/gi, '$1\n')
            // Remove remaining HTML tags
            .replace(/<[^>]+>/g, '')
            // Clean up multiple newlines
            .replace(/\n\s*\n\s*\n/g, '\n\n')
            .trim();

        return markdown;
    }

    /**
     * Convert Markdown to HTML
     * @param {string} markdown - Markdown content
     */
    markdownToHtml(markdown) {
        let html = markdown
            // Headers
            .replace(/^# (.*$)/gim, '<h1>$1</h1>')
            .replace(/^## (.*$)/gim, '<h2>$1</h2>')
            .replace(/^### (.*$)/gim, '<h3>$1</h3>')
            .replace(/^#### (.*$)/gim, '<h4>$1</h4>')
            .replace(/^##### (.*$)/gim, '<h5>$1</h5>')
            .replace(/^###### (.*$)/gim, '<h6>$1</h6>')
            // Bold and italic
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            // Strikethrough
            .replace(/~~(.*?)~~/g, '<s>$1</s>')
            // Code
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/```([\s\S]*?)```/g, '<pre>$1</pre>')
            // Links
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
            // Images
            .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1">')
            // Blockquotes
            .replace(/^> (.*$)/gim, '<blockquote>$1</blockquote>')
            // Lists
            .replace(/^\- (.*$)/gim, '<ul><li>$1</li></ul>')
            .replace(/^\d+\. (.*$)/gim, '<ol><li>$1</li></ol>')
            // Line breaks
            .replace(/\n/g, '<br>');

        return `<html><body>${html}</body></html>`;
    }

    /**
     * Convert HTML to plain text
     * @param {string} html - HTML content
     */
    htmlToText(html) {
        return html
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<p[^>]*>(.*?)<\/p>/gi, '$1\n\n')
            .replace(/<div[^>]*>(.*?)<\/div>/gi, '$1\n')
            .replace(/<[^>]+>/g, '')
            .replace(/\n\s*\n/g, '\n\n')
            .trim();
    }

    /**
     * Convert Markdown to plain text
     * @param {string} markdown - Markdown content
     */
    markdownToText(markdown) {
        return markdown
            .replace(/^#{1,6} /gm, '') // Remove headers
            .replace(/\*\*(.*?)\*\*/g, '$1') // Remove bold
            .replace(/\*(.*?)\*/g, '$1') // Remove italic
            .replace(/~~(.*?)~~/g, '$1') // Remove strikethrough
            .replace(/`(.*?)`/g, '$1') // Remove inline code
            .replace(/```[\s\S]*?```/g, '') // Remove code blocks
            .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // Remove links, keep text
            .replace(/!\[([^\]]*)\]\([^)]+\)/g, '$1') // Remove images, keep alt text
            .replace(/^> /gm, '') // Remove blockquote markers
            .replace(/^[\-\*\+] /gm, '') // Remove list markers
            .replace(/^\d+\. /gm, '') // Remove numbered list markers
            .trim();
    }

    /**
     * Convert plain text to Markdown
     * @param {string} text - Plain text content
     */
    textToMarkdown(text) {
        // Simple text to markdown conversion
        // This is basic - you might want to use a more sophisticated approach
        return text
            .split('\n')
            .map(line => {
                line = line.trim();
                if (line === '') return '';

                // Detect potential headers (all caps or title case)
                if (line.length < 50 && (line === line.toUpperCase() || this.isTitleCase(line))) {
                    return `## ${line}`;
                }

                // Detect potential lists (lines starting with numbers or dashes)
                if (/^\d+\./.test(line)) {
                    return line;
                }
                if (/^[\-\*\+]/.test(line)) {
                    return line;
                }

                return line;
            })
            .join('\n\n');
    }

    /**
     * Convert plain text to HTML
     * @param {string} text - Plain text content
     */
    textToHtml(text) {
        return text
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br>')
            .replace(/^/, '<p>')
            .replace(/$/, '</p>');
    }

    /**
     * Normalize file format extension
     * @param {string} format - File format
     */
    normalizeFormat(format) {
        if (!format.startsWith('.')) {
            format = '.' + format;
        }
        return format.toLowerCase();
    }

    /**
     * Check if text is in title case
     * @param {string} text - Text to check
     */
    isTitleCase(text) {
        return text.split(' ').every(word =>
            word.length === 0 || word[0] === word[0].toUpperCase()
        );
    }

    /**
     * Get file format from filename
     * @param {string} filename - Filename
     */
    getFileFormat(filename) {
        const ext = path.extname(filename).toLowerCase();
        return this.supportedFormats.input.includes(ext) ? ext : '.txt';
    }

    /**
     * Check if conversion is supported
     * @param {string} fromFormat - Source format
     * @param {string} toFormat - Target format
     */
    isConversionSupported(fromFormat, toFormat) {
        fromFormat = this.normalizeFormat(fromFormat);
        toFormat = this.normalizeFormat(toFormat);

        const supportedConversions = [
            ['.html', '.md'],
            ['.md', '.html'],
            ['.html', '.txt'],
            ['.md', '.txt'],
            ['.txt', '.md'],
            ['.txt', '.html']
        ];

        return supportedConversions.some(([from, to]) =>
            from === fromFormat && to === toFormat
        );
    }
}

module.exports = FileConverter;
