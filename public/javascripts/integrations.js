// Integrations page: connect note apps, import notes into Terp Notes, export files back.
// Imported notes get the same class details and checks as an upload (see utils/note-details.js).

const SEMESTERS = ['Fall', 'Spring', 'Summer', 'Winter', 'Unknown'];
const CATEGORIES = [
    ['Lecture Notes', '📚 Lecture Notes'],
    ['Study Guide', '📖 Study Guide'],
    ['Exam', '📝 Exam'],
    ['Homework', '✏️ Homework'],
    ['Cheat Sheet', '🗒️ Cheat Sheet'],
    ['Practice Problems', '🔢 Practice Problems'],
    ['Project', '💻 Project'],
    ['Lab', '🧪 Lab'],
    ['Textbook', '📕 Textbook'],
    ['Other', '📎 Other']
];
const COURSE_CODE = /^[A-Z]{2,5}\d{3}[A-Z]?$/;

/** Escapes text for HTML. Names of docs and accounts come from other apps. */
function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function getJson(url, options = {}) {
    const response = await fetch(url, { credentials: 'include', headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}) }, ...options });
    const data = await response.json().catch(() => null);
    if (response.status === 401) throw new Error('Your session ended. Sign in again to continue.');
    if (!data) throw new Error(`The server didn't answer properly (${response.status}). Try again in a moment.`);
    return { ok: response.ok && data.success !== false, status: response.status, data };
}

class IntegrationsManager {
    constructor() {
        const page = document.querySelector('.integrations-page');
        this.hasCatalog = page?.dataset.catalog === 'true';
        this.term = { semester: page?.dataset.semester || '', year: page?.dataset.year || String(new Date().getFullYear()) };
        this.integrations = [];
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.handleUrlParameters();
        await this.refresh();
    }

    async refresh() {
        const grid = document.getElementById('integrationsGrid');
        try {
            const { ok, data } = await getJson('/api/integrations');
            if (!ok) throw new Error(data.error || 'Could not load your integrations.');
            this.integrations = data.integrations || [];
            this.renderIntegrations();
        } catch (error) {
            grid.innerHTML = `
                <div class="integrations-empty" role="alert">
                    <p>${esc(error.message)}</p>
                    <button class="btn btn-secondary" onclick="integrationsManager.refresh()">Try again</button>
                </div>`;
        } finally {
            grid.setAttribute('aria-busy', 'false');
        }
    }

    handleUrlParameters() {
        const params = new URLSearchParams(window.location.search);
        const success = params.get('success');
        const error = params.get('error');
        const messages = {
            connected: 'Connected. You can import notes now.',
            google_connected: 'Google Drive connected. You can import notes now.',
            microsoft_connected: 'OneNote connected. You can import notes now.',
            notion_connected: 'Notion connected. You can import notes now.'
        };
        if (success && messages[success]) this.showNotification(messages[success], 'success');
        else if (error) this.showNotification(`Couldn't connect: ${error}`, 'error');
        if (success || error) window.history.replaceState({}, document.title, window.location.pathname);
    }

    // ---------- cards ----------

    renderIntegrations() {
        const grid = document.getElementById('integrationsGrid');
        if (!this.integrations.length) {
            grid.innerHTML = '<div class="integrations-empty"><p>No integrations are available right now.</p></div>';
            return;
        }
        // Connected apps first, then ones you can connect, then unavailable ones.
        const order = i => (i.isConnected ? 0 : i.unavailable || i.oauthConfigured === false ? 2 : 1);
        grid.innerHTML = [...this.integrations].sort((a, b) => order(a) - order(b)).map(i => this.cardHTML(i)).join('');
    }

    cardHTML(integration) {
        const account = this.formatConnectedAccount(integration.connectedAccount);
        const status = integration.isConnected
            ? '<span class="status-indicator status-connected">Connected</span>'
            : '';
        return `
            <article class="integration-card ${integration.isConnected ? 'connected' : ''}">
                <div class="integration-header">
                    <div class="integration-icon ${this.getIconClass(integration.id)}" aria-hidden="true">${this.getIconText(integration.id)}</div>
                    <h3 class="integration-title">${esc(integration.name)}</h3>
                    ${status}
                </div>
                <p class="integration-description">${esc(integration.description)}</p>
                ${account ? `<p class="connected-account">Signed in as ${esc(account)}</p>` : ''}
                <div class="integration-actions">${this.actionButtons(integration)}</div>
            </article>`;
    }

    actionButtons(integration) {
        const id = esc(integration.id);
        if (integration.isConnected) {
            const canExport = (integration.features || []).includes('export');
            return `
                <button class="btn btn-primary" onclick="integrationsManager.showActionModal('${id}', 'import')">Import notes</button>
                ${canExport ? `<button class="btn btn-secondary" onclick="integrationsManager.showActionModal('${id}', 'export')">Export a file</button>` : ''}
                <button class="btn btn-link" onclick="integrationsManager.disconnectIntegration('${id}')">Disconnect</button>`;
        }
        if (integration.unavailable) return '<button class="btn btn-secondary" disabled>Not available on the web</button>';
        if (integration.oauthSupported) {
            if (integration.oauthConfigured === false) return '<button class="btn btn-secondary" disabled>Coming soon</button>';
            return `<button class="btn btn-primary" onclick="integrationsManager.startOAuthFlow('${id}')">${esc(integration.connectLabel || `Connect ${integration.name}`)}</button>`;
        }
        return `<button class="btn btn-primary" onclick="integrationsManager.showConnectModal('${id}')">Connect</button>`;
    }

    formatConnectedAccount(account) {
        if (!account) return '';
        if (typeof account === 'string') return account;
        return account.email || account.name || '';
    }

    // ---------- connecting ----------

    startOAuthFlow(integrationId) {
        const integration = this.integrations.find(i => i.id === integrationId);
        const provider = integration?.oauthProvider || { notion: 'notion', onenote: 'microsoft', 'google-docs': 'google' }[integrationId];
        if (!provider) return this.showNotification('This app can\'t be connected yet.', 'error');
        window.location.href = `/auth/${provider}`;
    }

    showConnectModal(integrationId) {
        const integration = this.integrations.find(i => i.id === integrationId);
        if (!integration) return;
        const fields = {
            notion: [['integrationToken', 'Notion integration token', 'password', 'Create one at notion.so/my-integrations, then share your pages with it.']],
            onenote: [['accessToken', 'Microsoft access token', 'password', 'From Microsoft Graph Explorer.']],
        }[integrationId];
        document.getElementById('modalTitle').textContent = `Connect ${integration.name}`;
        document.getElementById('modalBody').innerHTML = fields
            ? `<form id="connectForm" novalidate>
                ${fields.map(([name, label, type, help]) => `
                    <div class="form-group">
                        <label class="form-label" for="cf-${name}">${esc(label)}</label>
                        <input id="cf-${name}" name="${name}" type="${type}" class="form-input" required autocomplete="off">
                        <div class="form-help">${esc(help)}</div>
                    </div>`).join('')}
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">Connect</button>
                    <button type="button" class="btn btn-secondary" onclick="integrationsManager.closeModal()">Cancel</button>
                </div>
            </form>`
            : '<p>This app connects with a sign-in button instead.</p>';
        const form = document.getElementById('connectForm');
        form?.addEventListener('submit', e => {
            e.preventDefault();
            this.connectIntegration(integrationId, Object.fromEntries(new FormData(form)));
        });
        this.openModal('integrationModal');
    }

    async connectIntegration(integrationId, credentials) {
        if (Object.values(credentials).some(v => !String(v).trim())) return this.showNotification('Fill in every field to connect.', 'error');
        try {
            const { ok, data } = await getJson(`/api/integrations/${integrationId}/initialize`, { method: 'POST', body: JSON.stringify({ credentials }) });
            if (!ok) throw new Error(data.error || 'Could not connect.');
            this.showNotification('Connected. You can import notes now.', 'success');
            this.closeModal();
            await this.refresh();
        } catch (error) {
            this.showNotification(error.message, 'error');
        }
    }

    async disconnectIntegration(integrationId) {
        const integration = this.integrations.find(i => i.id === integrationId);
        const name = integration?.name || 'this app';
        if (!confirm(`Disconnect ${name}? Notes you already imported stay on Terp Notes.`)) return;
        try {
            const { ok, data } = await getJson(`/api/integrations/${integrationId}`, { method: 'DELETE' });
            if (!ok) throw new Error(data.error || 'Could not disconnect.');
            this.showNotification(`${name} disconnected.`, 'success');
            await this.refresh();
        } catch (error) {
            this.showNotification(error.message, 'error');
        }
    }

    // ---------- import / export ----------

    async showActionModal(integrationId, action) {
        const integration = this.integrations.find(i => i.id === integrationId);
        if (!integration) return;
        const body = document.getElementById('actionModalBody');
        document.getElementById('actionModalTitle').textContent = action === 'import'
            ? `Import from ${integration.name}`
            : `Export to ${integration.name}`;
        body.innerHTML = `<p class="loading-line">Loading your ${esc(integration.name)} notes…</p>`;
        this.openModal('actionModal');

        let sources;
        try {
            sources = await this.loadSources(integrationId);
        } catch (error) {
            body.innerHTML = `<p class="form-error">${esc(error.message)}</p>
                <div class="form-actions"><button class="btn btn-secondary" onclick="integrationsManager.showActionModal('${esc(integrationId)}', '${action}')">Try again</button></div>`;
            return;
        }
        if (!sources.length) {
            const hints = {
                notion: 'No Notion pages were shared with Terp Notes. In Notion, open a page, choose ••• → Connections, and add Terp Notes.',
                onenote: 'No OneNote sections were found on this Microsoft account.',
                'google-docs': 'No Google Docs, Word files or PDFs were found in your Drive.'
            };
            body.innerHTML = `<p class="form-error">${esc(hints[integrationId] || 'No notes were found for this account.')}</p>`;
            return;
        }
        if (action === 'import') this.renderImportForm(integrationId, integration, sources);
        else await this.renderExportForm(integrationId, sources);
    }

    async loadSources(integrationId) {
        const { ok, data } = await getJson(`/api/integrations/${integrationId}/data`);
        if (!ok) throw new Error(data.error || 'Could not load your notes from this app.');
        const payload = data.data || {};
        if (Array.isArray(payload.sources) && payload.sources.length) return payload.sources;
        if (Array.isArray(payload.documents)) return payload.documents.map(d => ({ id: d.id, name: d.name }));
        if (Array.isArray(payload.databases)) return payload.databases.map(d => ({ id: d.id, name: d.title }));
        if (Array.isArray(payload.notebooks)) return payload.notebooks.map(n => ({ id: n.id, name: n.displayName }));
        return [];
    }

    sourceLabel(integrationId) {
        return integrationId === 'onenote' ? 'Section' : integrationId === 'notion' ? 'Page' : 'Document';
    }

    renderImportForm(integrationId, integration, sources) {
        const body = document.getElementById('actionModalBody');
        const label = this.sourceLabel(integrationId);
        const thisYear = Number(this.term.year) || new Date().getFullYear();
        const years = [];
        for (let y = thisYear + 1; y >= thisYear - 10; y--) years.push(y);
        const many = sources.length > 8;

        body.innerHTML = `
            <form id="importForm" class="import-form" novalidate>
                <fieldset>
                    <legend>${esc(label)}</legend>
                    ${many ? `<input type="search" id="sourceFilter" class="form-input" placeholder="Filter ${sources.length} items…" aria-label="Filter">` : ''}
                    <select id="sourceSelect" name="sourceId" class="form-input" ${many ? 'size="6"' : ''} required aria-label="${esc(label)} to import">
                        ${sources.map((s, i) => `<option value="${esc(s.id)}" ${i === 0 ? 'selected' : ''}>${esc(s.name || 'Untitled')}</option>`).join('')}
                    </select>
                </fieldset>

                <fieldset>
                    <legend>Class details</legend>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label" for="classCode">Class code <span class="required">*</span></label>
                            <div class="combo">
                            <input type="text" id="classCode" name="classCode" class="form-input" placeholder="e.g. CMSC330"
                                autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="12"
                                role="combobox" aria-expanded="false" aria-controls="courseList" aria-autocomplete="list" required>
                            <ul class="combo-list" id="courseList" role="listbox" hidden></ul>
                            </div>
                            <div class="form-help" id="courseInfo">${this.hasCatalog ? 'Start typing to search UMD courses.' : 'Your course code, e.g. CMSC331.'}</div>
                            <div class="field-error" data-for="classCode"></div>
                        </div>
                        <div class="form-group">
                            <label class="form-label" for="professor">Professor <span class="required">*</span></label>
                            <div class="combo">
                            <input type="text" id="professor" name="professor" class="form-input" placeholder="Professor's name"
                                autocomplete="off" maxlength="80" role="combobox" aria-expanded="false" aria-controls="professorList" aria-autocomplete="list" required>
                            <ul class="combo-list" id="professorList" role="listbox" hidden></ul>
                            </div>
                            <div class="form-help" id="professorHelp">${this.hasCatalog ? 'Pick a course to see who teaches it.' : ''}</div>
                            <div class="field-error" data-for="professor"></div>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label" for="semester">Semester <span class="required">*</span></label>
                            <select id="semester" name="semester" class="form-input" required>
                                <option value="">Select semester</option>
                                ${SEMESTERS.map(s => `<option value="${s}" ${s === this.term.semester ? 'selected' : ''}>${s}</option>`).join('')}
                            </select>
                            <div class="field-error" data-for="semester"></div>
                        </div>
                        <div class="form-group">
                            <label class="form-label" for="year">Year <span class="required">*</span></label>
                            <select id="year" name="year" class="form-input" required>
                                <option value="">Select year</option>
                                ${years.map(y => `<option value="${y}" ${String(y) === String(thisYear) ? 'selected' : ''}>${y}</option>`).join('')}
                            </select>
                            <div class="field-error" data-for="year"></div>
                        </div>
                        <div class="form-group">
                            <label class="form-label" for="category">Category <span class="required">*</span></label>
                            <select id="category" name="category" class="form-input" required>
                                ${CATEGORIES.map(([v, text]) => `<option value="${v}">${text}</option>`).join('')}
                            </select>
                            <div class="field-error" data-for="category"></div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="description">Description <span class="required">*</span></label>
                        <input type="text" id="description" name="description" class="form-input" maxlength="300"
                            placeholder="e.g. Week 3 lecture notes, Midterm 1 review" required>
                        <div class="field-error" data-for="description"></div>
                    </div>
                </fieldset>

                <label class="checkbox-label">
                    <input type="checkbox" id="academicIntegrity" required>
                    <span><strong>Academic integrity</strong> <span class="required">*</span><br>
                    <span class="form-help">These notes are my own work or properly cited, and sharing them doesn't break UMD's academic integrity rules.</span></span>
                </label>
                <div class="field-error" data-for="academicIntegrity"></div>

                <p class="form-help">Imported notes are checked the same way as uploads. Anything that looks like personal information waits for an admin before others can see it.</p>
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary" id="importSubmit">Import and share</button>
                    <button type="button" class="btn btn-secondary" onclick="integrationsManager.closeActionModal()">Cancel</button>
                </div>
            </form>`;

        const form = document.getElementById('importForm');
        const select = document.getElementById('sourceSelect');
        const description = document.getElementById('description');
        // Default the description to the note's name until the student types their own.
        const syncDescription = () => {
            if (!description.dataset.edited) description.value = select.selectedOptions[0]?.textContent.trim().slice(0, 300) || '';
        };
        syncDescription();
        select.addEventListener('change', syncDescription);
        description.addEventListener('input', () => { description.dataset.edited = '1'; });

        const filter = document.getElementById('sourceFilter');
        filter?.addEventListener('input', () => {
            const q = filter.value.trim().toLowerCase();
            let first = null;
            for (const option of select.options) {
                const show = !q || option.textContent.toLowerCase().includes(q);
                option.hidden = !show;
                if (show && !first) first = option;
            }
            if (select.selectedOptions[0]?.hidden && first) { first.selected = true; syncDescription(); }
        });

        CoursePicker.attach({
            classInput: document.getElementById('classCode'),
            classList: document.getElementById('courseList'),
            profInput: document.getElementById('professor'),
            profList: document.getElementById('professorList'),
            courseInfo: document.getElementById('courseInfo'),
            profHelp: document.getElementById('professorHelp'),
            hasCatalog: this.hasCatalog,
            next: document.getElementById('semester')
        });
        form.addEventListener('submit', e => {
            e.preventDefault();
            this.performImport(integrationId, integration);
        });
        document.getElementById('classCode').focus();
    }

    showFieldErrors(fields = {}) {
        document.querySelectorAll('#importForm .field-error').forEach(el => {
            const message = fields[el.dataset.for] || '';
            el.textContent = message;
            const input = document.getElementById(el.dataset.for);
            if (input) input.setAttribute('aria-invalid', message ? 'true' : 'false');
        });
        const first = Object.keys(fields)[0];
        if (first) document.getElementById(first)?.focus();
    }

    validateImport(values) {
        const errors = {};
        if (!values.classCode) errors.classCode = 'Enter the class code, e.g. CMSC330.';
        else if (!COURSE_CODE.test(values.classCode)) errors.classCode = 'Use a class code like CMSC330 or HIST289I.';
        if (!values.professor) errors.professor = "Enter the professor's name.";
        if (!values.semester) errors.semester = 'Pick a semester.';
        if (!values.year) errors.year = 'Pick a year.';
        if (!values.category) errors.category = 'Pick a category.';
        if (!values.description) errors.description = 'Add a short description.';
        if (!document.getElementById('academicIntegrity').checked) errors.academicIntegrity = 'Confirm the academic integrity statement to share these notes.';
        return errors;
    }

    async performImport(integrationId, integration) {
        const form = document.getElementById('importForm');
        const raw = Object.fromEntries(new FormData(form));
        const sourceId = raw.sourceId;
        const sourceName = document.getElementById('sourceSelect').selectedOptions[0]?.textContent.trim() || 'your note';
        const options = {
            classCode: (raw.classCode || '').trim().toUpperCase(),
            professor: (raw.professor || '').trim(),
            semester: raw.semester,
            year: raw.year,
            category: raw.category,
            description: (raw.description || '').trim()
        };
        const errors = this.validateImport(options);
        if (!sourceId) errors.sourceSelect = 'Pick something to import.';
        this.showFieldErrors(errors);
        if (Object.keys(errors).length) return;

        const button = document.getElementById('importSubmit');
        button.disabled = true;
        button.textContent = 'Importing…';
        try {
            const { ok, data } = await getJson(`/api/integrations/${integrationId}/import`, { method: 'POST', body: JSON.stringify({ sourceId, options }) });
            if (!ok) {
                if (data.fields) this.showFieldErrors(data.fields);
                throw new Error(data.error || 'Import failed.');
            }
            this.renderImportResult(integrationId, integration, data, sourceName);
        } catch (error) {
            this.showNotification(error.message, 'error');
            button.disabled = false;
            button.textContent = 'Import and share';
        }
    }

    renderImportResult(integrationId, integration, result, sourceName) {
        const count = result.count || 0;
        const held = result.held || [];
        const failed = result.failed || [];
        const duplicates = result.duplicates || [];
        const classCode = result.classCode || '';
        const lines = [];
        if (count) lines.push(`<p class="result-main">${count === 1 ? `"${esc(sourceName)}" is` : `${count} files are`} now on Terp Notes${classCode ? ` under ${esc(classCode)}` : ''}.</p>`);
        if (held.length) lines.push(`<p class="result-note warn">${esc(held.join(', '))} may contain personal information, so an admin will review ${held.length === 1 ? 'it' : 'them'} before other students can see ${held.length === 1 ? 'it' : 'them'}.</p>`);
        if (duplicates.length) lines.push(`<p class="result-note">${esc(duplicates.join(', '))} ${duplicates.length === 1 ? 'was' : 'were'} already shared for this class and term, so ${duplicates.length === 1 ? 'it was' : 'they were'} skipped.</p>`);
        if (failed.length) lines.push(`<p class="result-note error">${esc(failed.join(', '))} couldn't be imported. Try exporting ${failed.length === 1 ? 'it' : 'them'} as a PDF and uploading instead.</p>`);
        if (!count && !held.length && !duplicates.length && !failed.length) lines.push('<p class="result-main">Nothing was imported: that item had no content we could read.</p>');

        document.getElementById('actionModalBody').innerHTML = `
            <div class="import-result" role="status">
                <div class="result-icon" aria-hidden="true">${count ? '✓' : 'i'}</div>
                ${lines.join('')}
                <div class="form-actions">
                    ${count && classCode ? `<a class="btn btn-primary" href="/dashboard?q=${encodeURIComponent(classCode)}">View ${esc(classCode)} notes</a>` : ''}
                    ${count && classCode ? `<a class="btn btn-secondary" href="/study?course=${encodeURIComponent(classCode)}">Study with them</a>` : ''}
                    <button class="btn btn-secondary" onclick="integrationsManager.showActionModal('${esc(integrationId)}', 'import')">Import another</button>
                </div>
            </div>`;
        if (count) this.showNotification(`Imported from ${integration.name}.`, 'success');
    }

    async renderExportForm(integrationId, sources) {
        const body = document.getElementById('actionModalBody');
        let files = [];
        try {
            const { data } = await getJson('/api/my-files');
            files = data.files || [];
        } catch {
            files = [];
        }
        if (!files.length) {
            body.innerHTML = '<p class="form-error">You haven\'t uploaded any files yet. Upload one from the dashboard, then export it here.</p>';
            return;
        }
        body.innerHTML = `
            <form id="exportForm" novalidate>
                <div class="form-group">
                    <label class="form-label" for="fileSelect">Your file</label>
                    <select id="fileSelect" name="fileId" class="form-input">
                        ${files.map(f => `<option value="${esc(f._id)}">${esc(f.originalName)}${f.classCode ? ` (${esc(f.classCode)})` : ''}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label" for="targetSelect">Send to ${esc(this.sourceLabel(integrationId).toLowerCase())}</label>
                    <select id="targetSelect" name="targetId" class="form-input">
                        ${sources.map(s => `<option value="${esc(s.id)}">${esc(s.name || 'Untitled')}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label" for="exportTitle">Title (optional)</label>
                    <input type="text" id="exportTitle" name="title" class="form-input" maxlength="120" placeholder="Leave empty to keep the file's name">
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary" id="exportSubmit">Export</button>
                    <button type="button" class="btn btn-secondary" onclick="integrationsManager.closeActionModal()">Cancel</button>
                </div>
            </form>`;
        document.getElementById('exportForm').addEventListener('submit', e => {
            e.preventDefault();
            this.performExport(integrationId, Object.fromEntries(new FormData(e.target)));
        });
    }

    async performExport(integrationId, { fileId, targetId, title }) {
        const button = document.getElementById('exportSubmit');
        button.disabled = true;
        button.textContent = 'Exporting…';
        try {
            const { ok, data } = await getJson(`/api/integrations/${integrationId}/export`, { method: 'POST', body: JSON.stringify({ fileId, targetId, title }) });
            if (!ok) throw new Error(data.error || 'Export failed.');
            this.showNotification('Exported.', 'success');
            this.closeActionModal();
        } catch (error) {
            this.showNotification(error.message, 'error');
            button.disabled = false;
            button.textContent = 'Export';
        }
    }

    // ---------- modals and notices ----------

    openModal(id) {
        const modal = document.getElementById(id);
        this.lastFocus = document.activeElement;
        modal.classList.add('show');
        document.body.classList.add('modal-open');
    }

    closeModal() {
        document.getElementById('integrationModal').classList.remove('show');
        this.afterClose();
    }

    closeActionModal() {
        document.getElementById('actionModal').classList.remove('show');
        this.afterClose();
    }

    afterClose() {
        if (!document.querySelector('.modal.show')) {
            document.body.classList.remove('modal-open');
            this.lastFocus?.focus?.();
        }
    }

    getIconClass(id) {
        return { notion: 'notion-icon', onenote: 'onenote-icon', 'google-docs': 'google-icon' }[id] || '';
    }

    getIconText(id) {
        return { notion: 'N', onenote: '📓', 'google-docs': 'G' }[id] || '📝';
    }

    showNotification(message, type = 'info') {
        const note = document.createElement('div');
        note.className = `notification notification-${type}`;
        note.setAttribute('role', type === 'error' ? 'alert' : 'status');
        note.textContent = message;
        document.body.appendChild(note);
        setTimeout(() => {
            note.classList.add('leaving');
            setTimeout(() => note.remove(), 300);
        }, type === 'error' ? 6000 : 3500);
    }

    setupEventListeners() {
        document.addEventListener('click', e => {
            if (e.target.classList.contains('modal')) {
                this.closeModal();
                this.closeActionModal();
            }
        });
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && document.querySelector('.modal.show')) {
                this.closeModal();
                this.closeActionModal();
            }
        });
    }
}

function closeModal() {
    integrationsManager.closeModal();
}

function closeActionModal() {
    integrationsManager.closeActionModal();
}

document.addEventListener('DOMContentLoaded', () => {
    window.integrationsManager = new IntegrationsManager();
});
