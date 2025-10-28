// Integrations Management JavaScript

class IntegrationsManager {
    constructor() {
        this.integrations = [];
        this.connectedIntegrations = new Set();
        this.init();
    }

    async init() {
        await this.loadIntegrations();
        this.renderIntegrations();
        this.setupEventListeners();
        this.handleUrlParameters();
    }

    handleUrlParameters() {
        const urlParams = new URLSearchParams(window.location.search);
        const success = urlParams.get('success');
        const error = urlParams.get('error');

        if (success === 'connected') {
            this.showNotification('Integration connected successfully!', 'success');
            // Clean up URL
            window.history.replaceState({}, document.title, window.location.pathname);
        } else if (error) {
            this.showNotification(`Connection failed: ${decodeURIComponent(error)}`, 'error');
            // Clean up URL
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }

    async loadIntegrations() {
        try {
            const response = await fetch('/api/integrations', {
                credentials: 'include'
            });
            const data = await response.json();

            if (data.success) {
                this.integrations = data.integrations;
            } else {
                this.showNotification('Failed to load integrations', 'error');
            }
        } catch (error) {
            console.error('Error loading integrations:', error);
            this.showNotification('Error loading integrations', 'error');
        }
    }

    renderIntegrations() {
        const grid = document.getElementById('integrationsGrid');
        grid.innerHTML = '';

        this.integrations.forEach(integration => {
            const card = this.createIntegrationCard(integration);
            grid.appendChild(card);
        });
    }

    createIntegrationCard(integration) {
        const card = document.createElement('div');
        card.className = `integration-card ${integration.isConnected ? 'connected' : ''}`;

        // Show connected account info if available
        const connectedAccountInfo = integration.connectedAccount ?
            `<div class="connected-account">
                <small style="color: #059669; font-weight: 500;">
                    Connected as: ${integration.connectedAccount.email || integration.connectedAccount.name || 'Connected'}
                </small>
            </div>` : '';

        card.innerHTML = `
            <div class="integration-header">
                <div class="integration-icon ${this.getIconClass(integration.id)}">${this.getIconText(integration.id)}</div>
                <h3 class="integration-title">${integration.name}</h3>
                ${integration.isConnected ? '<span class="status-indicator status-connected">✅ Connected</span>' : ''}
            </div>
            <p class="integration-description">${integration.description}</p>
            ${connectedAccountInfo}
            <div class="integration-features">
                ${integration.features.map(feature =>
                    `<span class="feature-badge ${feature}">${feature.charAt(0).toUpperCase() + feature.slice(1)}</span>`
                ).join('')}
                ${integration.oauthSupported ? '<span class="feature-badge" style="background: #dbeafe; color: #1e40af;">OAuth</span>' : ''}
            </div>
            <div class="integration-actions">
                ${this.createActionButtons(integration)}
            </div>
        `;

        return card;
    }

    createActionButtons(integration) {
        const isConnected = integration.isConnected;

        if (isConnected) {
            return `
                <button class="btn btn-success" onclick="integrationsManager.showActionModal('${integration.id}', 'import')">
                    📥 Import
                </button>
                <button class="btn btn-primary" onclick="integrationsManager.showActionModal('${integration.id}', 'export')">
                    📤 Export
                </button>
                <button class="btn btn-danger" onclick="integrationsManager.disconnectIntegration('${integration.id}')">
                    Disconnect
                </button>
            `;
        } else {
            if (integration.oauthSupported) {
                return `
                    <button class="btn btn-primary" onclick="integrationsManager.startOAuthFlow('${integration.id}')">
                        🔐 Connect with OAuth
                    </button>
                `;
            } else {
                return `
                    <button class="btn btn-primary" onclick="integrationsManager.showConnectModal('${integration.id}')">
                        Connect
                    </button>
                `;
            }
        }
    }

    showConnectModal(integrationId) {
        const integration = this.integrations.find(i => i.id === integrationId);
        if (!integration) return;

        const modal = document.getElementById('integrationModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalBody = document.getElementById('modalBody');

        modalTitle.textContent = `Connect ${integration.name}`;
        modalBody.innerHTML = this.getConnectFormHTML(integration);

        modal.classList.add('show');
    }

    getConnectFormHTML(integration) {
        switch (integration.id) {
            case 'notion':
                return `
                    <div class="form-group">
                        <label class="form-label" for="notionToken">Notion Integration Token</label>
                        <input type="password" id="notionToken" class="form-input" placeholder="Enter your Notion integration token">
                        <div class="form-help">
                            Get your integration token from <a href="https://www.notion.so/my-integrations" target="_blank">Notion Integrations</a>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button class="btn btn-primary" onclick="integrationsManager.connectIntegration('notion')">
                            Connect
                        </button>
                        <button class="btn btn-secondary" onclick="integrationsManager.closeModal()">
                            Cancel
                        </button>
                    </div>
                `;
            case 'onenote':
                return `
                    <div class="form-group">
                        <label class="form-label" for="onenoteToken">Microsoft Access Token</label>
                        <input type="password" id="onenoteToken" class="form-input" placeholder="Enter your Microsoft access token">
                        <div class="form-help">
                            Get your access token from <a href="https://developer.microsoft.com/en-us/graph/quick-start" target="_blank">Microsoft Graph</a>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button class="btn btn-primary" onclick="integrationsManager.connectIntegration('onenote')">
                            Connect
                        </button>
                        <button class="btn btn-secondary" onclick="integrationsManager.closeModal()">
                            Cancel
                        </button>
                    </div>
                `;
            case 'google-docs':
                return `
                    <div class="form-group">
                        <label class="form-label" for="googleClientId">Google Client ID</label>
                        <input type="text" id="googleClientId" class="form-input" placeholder="Enter your Google Client ID">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="googleClientSecret">Google Client Secret</label>
                        <input type="password" id="googleClientSecret" class="form-input" placeholder="Enter your Google Client Secret">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="googleRedirectUri">Redirect URI</label>
                        <input type="text" id="googleRedirectUri" class="form-input" placeholder="Enter your redirect URI">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="googleAccessToken">Access Token</label>
                        <input type="password" id="googleAccessToken" class="form-input" placeholder="Enter your access token">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="googleRefreshToken">Refresh Token</label>
                        <input type="password" id="googleRefreshToken" class="form-input" placeholder="Enter your refresh token">
                    </div>
                    <div class="form-actions">
                        <button class="btn btn-primary" onclick="integrationsManager.connectIntegration('google-docs')">
                            Connect
                        </button>
                        <button class="btn btn-secondary" onclick="integrationsManager.closeModal()">
                            Cancel
                        </button>
                    </div>
                `;
            case 'obsidian':
                return `
                    <div class="form-group">
                        <label class="form-label" for="obsidianPath">Obsidian Vault Path</label>
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            <input type="text" id="obsidianPath" class="form-input" placeholder="/path/to/your/obsidian/vault" style="flex: 1;">
                            <button type="button" class="btn btn-secondary" onclick="integrationsManager.openFolderPicker()" style="white-space: nowrap;">
                                📁 Browse
                            </button>
                        </div>
                        <div class="form-help">
                            Enter the full path to your Obsidian vault folder or click Browse to select it
                        </div>
                    </div>
                    <div class="form-actions">
                        <button class="btn btn-primary" onclick="integrationsManager.connectIntegration('obsidian')">
                            Connect
                        </button>
                        <button class="btn btn-secondary" onclick="integrationsManager.closeModal()">
                            Cancel
                        </button>
                    </div>
                `;
            default:
                return '<p>Integration not supported yet.</p>';
        }
    }

    async startOAuthFlow(integrationId) {
        try {
            // Map integration IDs to OAuth providers
            const providerMap = {
                'notion': 'notion',
                'onenote': 'microsoft',
                'google-docs': 'google'
            };

            const provider = providerMap[integrationId];
            if (!provider) {
                this.showNotification('OAuth not supported for this integration', 'error');
                return;
            }

            // Direct redirect to OAuth provider (no fetch needed)
            window.location.href = `/auth/${provider}`;
        } catch (error) {
            console.error('Error starting OAuth flow:', error);
            this.showNotification('Error starting OAuth flow', 'error');
        }
    }

    async connectIntegration(integrationId) {
        const integration = this.integrations.find(i => i.id === integrationId);
        if (!integration) return;

        let credentials = {};

        switch (integrationId) {
            case 'notion':
                const notionToken = document.getElementById('notionToken').value;
                if (!notionToken) {
                    this.showNotification('Please enter your Notion integration token', 'error');
                    return;
                }
                credentials = { integrationToken: notionToken };
                break;
            case 'onenote':
                const onenoteToken = document.getElementById('onenoteToken').value;
                if (!onenoteToken) {
                    this.showNotification('Please enter your Microsoft access token', 'error');
                    return;
                }
                credentials = { accessToken: onenoteToken };
                break;
            case 'google-docs':
                const clientId = document.getElementById('googleClientId').value;
                const clientSecret = document.getElementById('googleClientSecret').value;
                const redirectUri = document.getElementById('googleRedirectUri').value;
                const accessToken = document.getElementById('googleAccessToken').value;
                const refreshToken = document.getElementById('googleRefreshToken').value;

                if (!clientId || !clientSecret || !accessToken || !refreshToken) {
                    this.showNotification('Please fill in all required fields', 'error');
                    return;
                }
                credentials = { clientId, clientSecret, redirectUri, accessToken, refreshToken };
                break;
            case 'obsidian':
                const vaultPath = document.getElementById('obsidianPath').value;
                if (!vaultPath) {
                    this.showNotification('Please enter your Obsidian vault path', 'error');
                    return;
                }
                credentials = { vaultPath };
                break;
        }

        try {
            const response = await fetch(`/api/integrations/${integrationId}/initialize`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify({ credentials })
            });

            const result = await response.json();

            if (result.success) {
                this.showNotification(`${integration.name} connected successfully!`, 'success');
                this.closeModal();
                this.loadIntegrations(); // Reload to get updated status
            } else {
                this.showNotification(result.error || 'Failed to connect integration', 'error');
            }
        } catch (error) {
            console.error('Error connecting integration:', error);
            this.showNotification('Error connecting integration', 'error');
        }
    }

    async showActionModal(integrationId, action) {
        const integration = this.integrations.find(i => i.id === integrationId);
        if (!integration) return;

        const modal = document.getElementById('actionModal');
        const modalTitle = document.getElementById('actionModalTitle');
        const modalBody = document.getElementById('actionModalBody');

        modalTitle.textContent = `${action.charAt(0).toUpperCase() + action.slice(1)} from ${integration.name}`;
        modalBody.innerHTML = await this.getActionFormHTML(integrationId, action);

        modal.classList.add('show');
    }

    async getActionFormHTML(integrationId, action) {
        try {
            const response = await fetch(`/api/integrations/${integrationId}/data`, {
                credentials: 'include'
            });
            const data = await response.json();

            if (!data.success) {
                return `<p class="form-error">Failed to load ${integrationId} data: ${data.error}</p>`;
            }

            let optionsHTML = '';
            let sourceLabel = '';

            switch (integrationId) {
                case 'notion':
                    sourceLabel = 'Database';
                    if (data.data && data.data.databases && Array.isArray(data.data.databases)) {
                        optionsHTML = data.data.databases.map(db =>
                            `<option value="${db.id}">${db.title}</option>`
                        ).join('');
                    } else {
                        return `<p class="form-error">No databases available. Please check your Notion connection.</p>`;
                    }
                    break;
                case 'onenote':
                    sourceLabel = 'Notebook';
                    if (data.data && data.data.notebooks && Array.isArray(data.data.notebooks)) {
                        optionsHTML = data.data.notebooks.map(notebook =>
                            `<option value="${notebook.id}">${notebook.displayName}</option>`
                        ).join('');
                    } else {
                        return `<p class="form-error">No notebooks available. Please check your OneNote connection.</p>`;
                    }
                    break;
                case 'google-docs':
                    sourceLabel = 'Document';
                    if (data.data && data.data.documents && Array.isArray(data.data.documents)) {
                        optionsHTML = data.data.documents.map(doc =>
                            `<option value="${doc.id}">${doc.name}</option>`
                        ).join('');
                    } else {
                        return `<p class="form-error">No documents available. Please check your Google Docs connection.</p>`;
                    }
                    break;
                case 'obsidian':
                    sourceLabel = 'Folder';
                    optionsHTML = '<option value="">Root folder</option>';
                    if (data.data && data.data.files && Array.isArray(data.data.files)) {
                        optionsHTML += this.buildObsidianOptions(data.data.files);
                    } else {
                        return `<p class="form-error">No files available. Please check your Obsidian vault path.</p>`;
                    }
                    break;
            }

            if (action === 'import') {
                return `
                    <div class="form-group">
                        <label class="form-label" for="sourceSelect">Select ${sourceLabel}</label>
                        <select id="sourceSelect" class="form-input">
                            ${optionsHTML}
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="classCode">Class Code (Optional)</label>
                        <input type="text" id="classCode" class="form-input" placeholder="e.g., CMSC330">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="professor">Professor (Optional)</label>
                        <input type="text" id="professor" class="form-input" placeholder="Professor name">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="semester">Semester (Optional)</label>
                        <select id="semester" class="form-input">
                            <option value="">Select semester</option>
                            <option value="Spring">Spring</option>
                            <option value="Summer">Summer</option>
                            <option value="Fall">Fall</option>
                            <option value="Winter">Winter</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="year">Year (Optional)</label>
                        <input type="number" id="year" class="form-input" placeholder="2024" min="2020" max="2030">
                    </div>
                    <div class="form-actions">
                        <button class="btn btn-success" onclick="integrationsManager.performImport('${integrationId}')">
                            📥 Import Notes
                        </button>
                        <button class="btn btn-secondary" onclick="integrationsManager.closeActionModal()">
                            Cancel
                        </button>
                    </div>
                `;
            } else {
                return `
                    <div class="form-group">
                        <label class="form-label" for="fileSelect">Select File to Export</label>
                        <select id="fileSelect" class="form-input">
                            <option value="">Loading files...</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="targetSelect">Target ${sourceLabel}</label>
                        <select id="targetSelect" class="form-input">
                            ${optionsHTML}
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="exportTitle">Export Title (Optional)</label>
                        <input type="text" id="exportTitle" class="form-input" placeholder="Custom title for exported content">
                    </div>
                    <div class="form-actions">
                        <button class="btn btn-primary" onclick="integrationsManager.performExport('${integrationId}')">
                            📤 Export Notes
                        </button>
                        <button class="btn btn-secondary" onclick="integrationsManager.closeActionModal()">
                            Cancel
                        </button>
                    </div>
                `;
            }
        } catch (error) {
            console.error('Error loading action form:', error);
            return `<p class="form-error">Error loading form: ${error.message}</p>`;
        }
    }

    buildObsidianOptions(structure, prefix = '') {
        let options = '';
        for (const item of structure) {
            if (item.type === 'folder') {
                const path = prefix + item.name;
                options += `<option value="${path}">${path}</option>`;
                if (item.children) {
                    options += this.buildObsidianOptions(item.children, path + '/');
                }
            }
        }
        return options;
    }

    async performImport(integrationId) {
        const sourceId = document.getElementById('sourceSelect').value;
        if (!sourceId) {
            this.showNotification('Please select a source', 'error');
            return;
        }

        const options = {
            classCode: document.getElementById('classCode').value,
            professor: document.getElementById('professor').value,
            semester: document.getElementById('semester').value,
            year: document.getElementById('year').value
        };

        try {
            const response = await fetch(`/api/integrations/${integrationId}/import`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify({ sourceId, options })
            });

            const result = await response.json();

            if (result.success) {
                this.showNotification(`Successfully imported ${result.count || 1} file(s)!`, 'success');
                this.closeActionModal();
            } else {
                this.showNotification(result.error || 'Import failed', 'error');
            }
        } catch (error) {
            console.error('Error importing:', error);
            this.showNotification('Error importing files', 'error');
        }
    }

    async performExport(integrationId) {
        const fileId = document.getElementById('fileSelect').value;
        const targetId = document.getElementById('targetSelect').value;
        const title = document.getElementById('exportTitle').value;

        if (!fileId) {
            this.showNotification('Please select a file to export', 'error');
            return;
        }

        if (!targetId) {
            this.showNotification('Please select a target', 'error');
            return;
        }

        try {
            const response = await fetch(`/api/integrations/${integrationId}/export`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify({ fileId, targetId, title })
            });

            const result = await response.json();

            if (result.success) {
                this.showNotification('File exported successfully!', 'success');
                this.closeActionModal();
            } else {
                this.showNotification(result.error || 'Export failed', 'error');
            }
        } catch (error) {
            console.error('Error exporting:', error);
            this.showNotification('Error exporting file', 'error');
        }
    }

    async disconnectIntegration(integrationId) {
        if (!confirm('Are you sure you want to disconnect this integration?')) {
            return;
        }

        try {
            const response = await fetch(`/api/integrations/${integrationId}`, {
                method: 'DELETE',
                credentials: 'include'
            });

            const result = await response.json();

            if (result.success) {
                this.connectedIntegrations.delete(integrationId);
                this.showNotification('Integration disconnected', 'success');
                // Reload integrations data from server and re-render
                await this.loadIntegrations();
                this.renderIntegrations();
            } else {
                this.showNotification('Failed to disconnect integration', 'error');
            }
        } catch (error) {
            console.error('Error disconnecting integration:', error);
            this.showNotification('Error disconnecting integration', 'error');
        }
    }

    closeModal() {
        document.getElementById('integrationModal').classList.remove('show');
    }

    closeActionModal() {
        document.getElementById('actionModal').classList.remove('show');
    }

    getIconClass(integrationId) {
        const iconMap = {
            'notion': 'notion-icon',
            'onenote': 'onenote-icon',
            'google-docs': 'google-icon',
            'obsidian': 'obsidian-icon'
        };
        return iconMap[integrationId] || 'integration-icon';
    }

    getIconText(integrationId) {
        const textMap = {
            'notion': 'N',
            'onenote': '📓',
            'google-docs': 'G',
            'obsidian': '⚡'
        };
        return textMap[integrationId] || '📝';
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;

        // Style the notification
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            animation: slideInRight 0.3s ease;
        `;

        // Set background color based on type
        switch (type) {
            case 'success':
                notification.style.backgroundColor = '#10b981';
                break;
            case 'error':
                notification.style.backgroundColor = '#ef4444';
                break;
            case 'warning':
                notification.style.backgroundColor = '#f59e0b';
                break;
            default:
                notification.style.backgroundColor = '#3b82f6';
        }

        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }

    setupEventListeners() {
        // Close modals when clicking outside
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                this.closeModal();
                this.closeActionModal();
            }
        });

        // Close modals with Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeModal();
                this.closeActionModal();
            }
        });
    }

    openFolderPicker() {
        // Create a hidden file input for folder selection
        const input = document.createElement('input');
        input.type = 'file';
        input.webkitdirectory = true; // Allow directory selection
        input.directory = true;
        input.multiple = true;

        input.onchange = (event) => {
            const files = event.target.files;
            if (files.length > 0) {
                // Get the directory path from the first file
                const firstFile = files[0];

                // Set the path in the input field
                const pathInput = document.getElementById('obsidianPath');
                if (pathInput) {
                    // Extract the full path (remove the filename part)
                    const fullPath = firstFile.path || firstFile.webkitRelativePath.split('/').slice(0, -1).join('/');
                    pathInput.value = fullPath;
                }
            }
        };

        // Trigger the file picker
        input.click();
    }
}

// Global functions for modal management
function closeModal() {
    integrationsManager.closeModal();
}

function closeActionModal() {
    integrationsManager.closeActionModal();
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.integrationsManager = new IntegrationsManager();
});

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);
