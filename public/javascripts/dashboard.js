// Dashboard: one responsive list of notes with search, filters, upload, edit, report, delete and
// bulk download. Replaces the old grouped/grid/list views and the separate /mobile pages.
(function () {
    const data = JSON.parse(document.getElementById('pageData').textContent);
    const { esc, COURSE_CODE } = window.CoursePicker;
    const me = data.user;
    const PAGE = 30;
    const CATEGORIES = ['Lecture Notes', 'Study Guide', 'Exam', 'Homework', 'Cheat Sheet', 'Practice Problems', 'Project', 'Lab', 'Textbook', 'Other'];
    const TERM_ORDER = { Winter: 0, Spring: 1, Summer: 2, Fall: 3 };
    const VIEWABLE = /^(application\/pdf|image\/|text\/)/;

    const $ = id => document.getElementById(id);
    const els = {
        q: $('q'), course: $('fCourse'), category: $('fCategory'), term: $('fTerm'), professor: $('fProfessor'),
        sort: $('fSort'), mine: $('fMine'), list: $('fileList'), empty: $('emptyState'), more: $('showMore'),
        count: $('resultCount'), clear: $('clearFilters'), filters: $('filters'), filtersToggle: $('filtersToggle'),
        filterCount: $('filterCount'), selectToggle: $('selectToggle'), selectBar: $('selectBar'),
        selectedCount: $('selectedCount'), bulkDownload: $('bulkDownload'), bulkDelete: $('bulkDelete'), bulkCancel: $('bulkCancel')
    };

    const files = data.files.map(f => ({
        ...f,
        time: new Date(f.uploadDate).getTime() || 0,
        term: f.semester && f.year ? `${f.semester} ${f.year}` : '',
        haystack: [f.name, f.description, f.classCode, f.professor, f.category, f.uploadedBy, f.semester, f.year].join(' ').toLowerCase()
    }));
    const byName = new Map(files.map(f => [f.filename, f]));
    const state = { shown: PAGE, selecting: false, selected: new Set() };
    const canManage = f => me.role !== 'viewer' && (me.role === 'admin' || f.uploadedBy === me.userid);

    // ---------- filters ----------

    function fillSelect(select, values, label = v => v) {
        const keep = select.value;
        select.length = 1;
        for (const v of values) select.add(new Option(label(v), v));
        if (values.includes(keep)) select.value = keep;
    }

    function termKey(t) {
        const [sem, year] = t.split(' ');
        return Number(year) * 10 + (TERM_ORDER[sem] ?? -1);
    }

    function buildFilters() {
        const uniq = list => [...new Set(list.filter(Boolean))];
        fillSelect(els.course, uniq(files.map(f => f.classCode)).sort());
        fillSelect(els.category, CATEGORIES.filter(c => files.some(f => f.category === c)).concat(uniq(files.map(f => f.category)).filter(c => !CATEGORIES.includes(c))));
        fillSelect(els.term, uniq(files.map(f => f.term)).sort((a, b) => termKey(b) - termKey(a)));
        refreshProfessors();
    }

    // Professors follow the chosen course, so the list stays short and relevant.
    function refreshProfessors() {
        const course = els.course.value;
        const pool = course ? files.filter(f => f.classCode === course) : files;
        fillSelect(els.professor, [...new Set(pool.map(f => f.professor).filter(Boolean))].sort((a, b) => a.localeCompare(b)));
    }

    function readUrl() {
        const p = new URLSearchParams(location.search);
        els.q.value = (p.get('q') || '').slice(0, 100);
        for (const [key, el] of [['course', els.course], ['type', els.category], ['term', els.term], ['prof', els.professor], ['sort', els.sort]]) {
            const v = p.get(key);
            if (v && [...el.options].some(o => o.value === v)) el.value = v;
        }
        els.mine.checked = p.get('mine') === '1';
        if (els.course.value) refreshProfessors();
    }

    function writeUrl() {
        const p = new URLSearchParams();
        if (els.q.value.trim()) p.set('q', els.q.value.trim());
        if (els.course.value) p.set('course', els.course.value);
        if (els.category.value) p.set('type', els.category.value);
        if (els.term.value) p.set('term', els.term.value);
        if (els.professor.value) p.set('prof', els.professor.value);
        if (els.sort.value !== 'newest') p.set('sort', els.sort.value);
        if (els.mine.checked) p.set('mine', '1');
        const qs = p.toString();
        history.replaceState(null, '', qs ? `?${qs}` : location.pathname);
        window.TerpShell?.markActive();
    }

    // Hands files to the Study Buddy panel (it lives in the app shell, on every page).
    function studyWith(list) {
        const usable = list.filter(f => f && !f.missing && !f.held).slice(0, 20);
        if (!usable.length || !window.StudyBuddy) return;
        const courses = [...new Set(usable.map(f => f.classCode).filter(Boolean))];
        window.StudyBuddy.open({ course: courses.length === 1 ? courses[0] : '', files: usable.map(f => ({ filename: f.filename, name: f.name })) });
    }

    // "My courses" in the sidebar: offer to add the course being browsed.
    function updatePin() {
        const btn = $('pinCourse');
        if (!btn) return;
        const course = els.course.value;
        const pinned = window.TerpShell ? window.TerpShell.pinned() : (data.pinnedCourses || []);
        btn.hidden = !course;
        if (!course) return;
        const on = pinned.includes(course);
        btn.textContent = on ? `${course} is in My courses` : `Add ${course} to My courses`;
        btn.setAttribute('aria-pressed', String(on));
    }

    function activeFilterCount() {
        return [els.course, els.category, els.term, els.professor].filter(el => el.value).length + (els.mine.checked ? 1 : 0);
    }

    function filtered() {
        const words = els.q.value.toLowerCase().split(/\s+/).filter(Boolean);
        const list = files.filter(f =>
            (!els.course.value || f.classCode === els.course.value) &&
            (!els.category.value || f.category === els.category.value) &&
            (!els.term.value || f.term === els.term.value) &&
            (!els.professor.value || f.professor === els.professor.value) &&
            (!els.mine.checked || f.uploadedBy === me.userid) &&
            words.every(w => f.haystack.includes(w))
        );
        const sorters = {
            newest: (a, b) => b.time - a.time,
            popular: (a, b) => b.downloads - a.downloads || b.time - a.time,
            name: (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true })
        };
        return list.sort(sorters[els.sort.value] || sorters.newest);
    }

    // ---------- rendering ----------

    function ext(name) {
        const m = /\.([a-z0-9]{1,5})$/i.exec(name || '');
        return m ? m[1].toUpperCase() : 'FILE';
    }

    function size(bytes) {
        if (!bytes) return '';
        if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
        return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
    }

    function ago(time) {
        if (!time) return '';
        const days = Math.floor((Date.now() - time) / 86400000);
        if (days < 1) return 'today';
        if (days === 1) return 'yesterday';
        if (days < 7) return `${days} days ago`;
        return new Date(time).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: new Date(time).getFullYear() === new Date().getFullYear() ? undefined : 'numeric' });
    }

    function row(f) {
        const href = `/download/${encodeURIComponent(f.filename)}`;
        const open = VIEWABLE.test(f.mimetype) ? href : `${href}?force=download`;
        const badges = [
            f.held ? '<span class="tn-badge tn-badge-warn held-for-review" title="Only you and admins can see this until an admin reviews it">Waiting for review</span>' : '',
            f.scanning ? '<span class="tn-badge" title="Virus scan in progress">Scanning</span>' : '',
            f.missing ? '<span class="tn-badge tn-badge-error">Unavailable</span>' : ''
        ].join('');
        const staff = f.staffRole ? `<span class="tn-staff staff-badge">${f.staffRole === 'professor' ? 'From the professor' : 'From a TA'}</span>` : '';
        const meta = [f.professor, f.term].filter(Boolean).map(esc).join(' · ');
        const checked = state.selected.has(f.filename) ? 'checked' : '';
        return `
            <li class="tn-file${state.selected.has(f.filename) ? ' is-selected' : ''}" data-filename="${esc(f.filename)}" data-name="${esc(f.name)}">
                <label class="tn-file-check"${state.selecting ? '' : ' hidden'}>
                    <input type="checkbox" data-select ${checked} aria-label="Select ${esc(f.name)}" />
                </label>
                <span class="tn-file-type tn-type-${esc(ext(f.name).toLowerCase())}" aria-hidden="true">${esc(ext(f.name))}</span>
                <div class="tn-file-main">
                    <a class="tn-file-name" href="${f.missing ? '#' : open}" ${VIEWABLE.test(f.mimetype) ? 'target="_blank" rel="noopener"' : ''} title="${esc(f.name)}">${esc(f.name)}</a>
                    ${badges ? `<div class="tn-badges">${badges}</div>` : ''}
                    <div class="tn-file-meta">
                        ${f.classCode ? `<button type="button" class="tn-chip" data-course="${esc(f.classCode)}" title="Show ${esc(f.classCode)} notes">${esc(f.classCode)}</button>` : ''}
                        <span class="tn-cat">${esc(f.category)}</span>
                        ${meta ? `<span>${meta}</span>` : ''}
                    </div>
                    ${f.description && f.description !== f.name ? `<p class="tn-file-desc">${esc(f.description)}</p>` : ''}
                    <div class="tn-file-sub">
                        <span>${esc(f.uploadedBy)}${staff}</span>
                        <span>${ago(f.time)}</span>
                        ${f.size ? `<span>${size(f.size)}</span>` : ''}
                        <span>${f.downloads} ${f.downloads === 1 ? 'download' : 'downloads'}</span>
                    </div>
                </div>
                <div class="tn-file-actions">
                    ${f.missing ? '' : `<a class="tn-btn tn-btn-outline tn-btn-sm" href="${href}?force=download" download aria-label="Download ${esc(f.name)}">
                        <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v12M6 10l6 6 6-6M4 20h16"/></svg><span>Download</span></a>`}
                    <details class="tn-menu">
                        <summary class="tn-icon-btn" aria-label="More actions for ${esc(f.name)}">
                            <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="19" cy="12" r="1.8"/></svg>
                        </summary>
                        <div class="tn-menu-list" role="menu">
                            ${f.missing ? '' : `<a role="menuitem" href="${href}" target="_blank" rel="noopener">Open in new tab</a>`}
                            ${f.missing || f.held ? '' : '<button type="button" role="menuitem" data-action="buddy">Ask Study Buddy</button>'}
                            <button type="button" role="menuitem" data-action="copy">Copy link</button>
                            ${canManage(f) ? '<button type="button" role="menuitem" data-action="edit">Edit details</button>' : ''}
                            ${f.uploadedBy !== me.userid ? '<button type="button" role="menuitem" data-action="report">Report</button>' : ''}
                            ${canManage(f) ? '<button type="button" role="menuitem" class="tn-danger-text" data-action="delete">Delete</button>' : ''}
                        </div>
                    </details>
                </div>
            </li>`;
    }

    function emptyHTML() {
        if (!files.length) {
            return `<h2>No notes yet</h2><p>Be the first to share notes for your classes.</p>${data.canUpload ? '<button type="button" class="tn-btn tn-btn-primary" data-open-upload>Upload notes</button>' : ''}`;
        }
        if (els.mine.checked && activeFilterCount() === 1 && !els.q.value.trim()) {
            return `<h2>You haven't uploaded anything yet</h2><p>Your uploads show up here.</p>${data.canUpload ? '<button type="button" class="tn-btn tn-btn-primary" data-open-upload>Upload notes</button>' : ''}`;
        }
        const course = els.course.value || (COURSE_CODE.test(els.q.value.trim().toUpperCase()) ? els.q.value.trim().toUpperCase() : '');
        return `<h2>No notes match</h2><p>Try fewer words or clear the filters.${course && data.canUpload ? ` Have notes for ${esc(course)}? Share them.` : ''}</p>
            <div class="tn-empty-actions"><button type="button" class="tn-btn tn-btn-outline" data-clear>Clear filters</button>${course && data.canUpload ? `<button type="button" class="tn-btn tn-btn-primary" data-open-upload data-course="${esc(course)}">Upload ${esc(course)} notes</button>` : ''}</div>`;
    }

    let current = [];
    function render() {
        current = filtered();
        const visible = current.slice(0, state.shown);
        els.list.innerHTML = visible.map(row).join('');
        els.empty.hidden = current.length > 0;
        if (!current.length) els.empty.innerHTML = emptyHTML();
        els.more.hidden = current.length <= state.shown;
        els.more.textContent = `Show more (${current.length - state.shown} left)`;
        const n = activeFilterCount();
        const searching = n > 0 || els.q.value.trim();
        els.count.textContent = searching
            ? `${current.length} of ${files.length} notes`
            : `${files.length} ${files.length === 1 ? 'note' : 'notes'}`;
        els.clear.hidden = !searching;
        els.filterCount.hidden = !n;
        els.filterCount.textContent = n;
        els.selectToggle.hidden = !files.length;
        updatePin();
        updateSelectBar();
    }

    const rerender = () => { state.shown = PAGE; writeUrl(); render(); };

    // ---------- selection ----------

    function setSelecting(on) {
        state.selecting = on;
        if (!on) state.selected.clear();
        els.selectToggle.textContent = on ? 'Done' : 'Select';
        document.body.classList.toggle('is-selecting', on);
        render();
    }

    function updateSelectBar() {
        const n = state.selected.size;
        els.selectBar.hidden = !state.selecting;
        els.selectedCount.textContent = n ? `${n} selected` : 'Select notes to download';
        els.bulkDownload.disabled = !n || n > 20;
        els.bulkDownload.title = n > 20 ? 'Up to 20 files per download' : '';
        const manageable = [...state.selected].every(fn => byName.get(fn) && canManage(byName.get(fn)));
        els.bulkDelete.hidden = !n || !manageable;
        if ($('bulkBuddy')) $('bulkBuddy').disabled = !n || n > 20;
    }

    async function bulkDownload() {
        const filenames = [...state.selected];
        els.bulkDownload.disabled = true;
        const done = toast(`Preparing ${filenames.length} files…`, 'info', 0);
        try {
            const res = await fetch('/bulk-download', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ filenames }) });
            if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Download failed.');
            const url = URL.createObjectURL(await res.blob());
            const a = Object.assign(document.createElement('a'), { href: url, download: `terp-notes-${filenames.length}-files.zip` });
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 10000);
            done();
            toast(`Downloaded ${filenames.length} files.`, 'success');
            setSelecting(false);
        } catch (err) {
            done();
            toast(err.message, 'error');
            updateSelectBar();
        }
    }

    async function deleteFiles(filenames) {
        const names = filenames.map(fn => byName.get(fn)?.name).filter(Boolean);
        const ok = await confirmBox(
            filenames.length === 1 ? `Delete "${names[0]}"?` : `Delete ${filenames.length} files?`,
            'Other students will no longer be able to find or download it. This can\'t be undone.'
        );
        if (!ok) return;
        try {
            const res = await fetch('/api/bulk-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ filenames }) });
            const body = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(body.error || 'Delete failed.');
            const gone = (body.results?.success || []).map(r => r.filename);
            for (const fn of gone) {
                const i = files.findIndex(f => f.filename === fn);
                if (i >= 0) files.splice(i, 1);
                byName.delete(fn);
                state.selected.delete(fn);
            }
            const failed = filenames.length - gone.length;
            toast(failed ? `Deleted ${gone.length}; ${failed} couldn't be deleted.` : `Deleted ${gone.length === 1 ? names[0] : `${gone.length} files`}.`, failed ? 'error' : 'success');
            if (state.selecting && !state.selected.size) setSelecting(false);
            buildFilters();
            render();
        } catch (err) {
            toast(err.message, 'error');
        }
    }

    // ---------- toasts and confirm ----------

    function toast(message, type = 'info', ms = 4000) {
        const el = document.createElement('div');
        el.className = `tn-toast tn-toast-${type}`;
        el.setAttribute('role', type === 'error' ? 'alert' : 'status');
        el.textContent = message;
        $('toasts').appendChild(el);
        const close = () => { el.classList.add('leaving'); setTimeout(() => el.remove(), 250); };
        if (ms) setTimeout(close, type === 'error' ? Math.max(ms, 6000) : ms);
        return close;
    }

    function confirmBox(title, text) {
        const dlg = $('confirmDialog');
        $('confirmTitle').textContent = title;
        $('confirmText').textContent = text;
        dlg.returnValue = '';
        dlg.showModal();
        return new Promise(resolve => dlg.addEventListener('close', () => resolve(dlg.returnValue === 'confirm'), { once: true }));
    }

    // ---------- upload and edit (one form) ----------

    const form = {
        dlg: $('noteDialog'), el: $('noteForm'), title: $('noteDialogTitle'), drop: $('dropZone'), input: $('fileInput'),
        picked: $('pickedFiles'), editing: $('editingName'), submit: $('noteSubmit'), status: $('uploadStatus'),
        progress: $('uploadProgress'), integrity: $('integrityRow'), note: $('uploadNote'),
        fields: ['classCode', 'professor', 'semester', 'year', 'category', 'description'].reduce((o, k) => ({ ...o, [k]: $(k) }), {})
    };
    let mode = 'upload';
    let editTarget = null;
    let chosen = [];
    let busy = false;

    (function setupForm() {
        const thisYear = Number(data.term?.year) || new Date().getFullYear();
        for (let y = thisYear + 1; y >= thisYear - 10; y--) form.fields.year.add(new Option(y, y));
        CATEGORIES.forEach(c => form.fields.category.add(new Option(c, c)));
        form.picker = CoursePicker.attach({
            classInput: form.fields.classCode, classList: $('courseList'), profInput: form.fields.professor, profList: $('professorList'),
            courseInfo: $('courseInfo'), profHelp: $('professorHelp'), hasCatalog: data.hasCourseCatalog, next: form.fields.semester
        });
    })();

    const allowed = new Set((data.allowedExtensions || []).map(e => e.toLowerCase()));
    function addFiles(list) {
        for (const file of list) {
            const dot = file.name.lastIndexOf('.');
            const extension = dot >= 0 ? file.name.slice(dot).toLowerCase() : '';
            let problem = '';
            if (allowed.size && !allowed.has(extension)) problem = `${extension || 'This type'} isn't supported`;
            else if (file.size > 100 * 1024 * 1024) problem = 'Over 100 MB';
            else if (!file.size) problem = 'Empty file';
            if (!chosen.some(c => c.file.name === file.name && c.file.size === file.size)) chosen.push({ file, problem });
        }
        renderPicked();
    }

    function renderPicked() {
        form.picked.innerHTML = chosen.map((c, i) => `
            <li class="${c.problem ? 'is-bad' : ''}">
                <span class="tn-file-type tn-type-${esc(ext(c.file.name).toLowerCase())}">${esc(ext(c.file.name))}</span>
                <span class="tn-picked-name">${esc(c.file.name)}<small>${c.problem ? esc(c.problem) : size(c.file.size)}</small></span>
                <button type="button" class="tn-icon-btn" data-remove="${i}" aria-label="Remove ${esc(c.file.name)}">&times;</button>
            </li>`).join('');
        const good = chosen.filter(c => !c.problem).length;
        form.submit.textContent = good > 1 ? `Upload ${good} files` : 'Upload';
        // The first file's name is a good starting description.
        if (good && !form.fields.description.dataset.edited) {
            form.fields.description.value = chosen.find(c => !c.problem).file.name.replace(/\.[^.]+$/, '').replace(/[_-]+/g, ' ').slice(0, 300);
        }
    }

    function clearErrors() {
        form.el.querySelectorAll('.tn-error').forEach(e => { e.textContent = ''; });
        form.el.querySelectorAll('[aria-invalid]').forEach(e => e.removeAttribute('aria-invalid'));
    }

    function showErrors(errors) {
        for (const [key, message] of Object.entries(errors)) {
            const slot = form.el.querySelector(`.tn-error[data-for="${key}"]`);
            if (slot) slot.textContent = message;
            const input = $(key);
            if (input) input.setAttribute('aria-invalid', 'true');
        }
        const first = Object.keys(errors)[0];
        if (first && $(first)) $(first).focus();
    }

    function values() {
        const v = Object.fromEntries(Object.entries(form.fields).map(([k, el]) => [k, el.value.trim()]));
        v.classCode = v.classCode.toUpperCase().replace(/\s+/g, '');
        return v;
    }

    function validate(v) {
        const e = {};
        if (!v.classCode) e.classCode = 'Enter the class code, e.g. CMSC330.';
        else if (!COURSE_CODE.test(v.classCode)) e.classCode = 'Use a class code like CMSC330 or HIST289I.';
        if (!v.professor) e.professor = "Enter the professor's name.";
        if (!v.semester) e.semester = 'Pick a semester.';
        if (!v.year) e.year = 'Pick a year.';
        if (!v.category) e.category = 'Pick a type.';
        if (!v.description) e.description = 'Add a short description.';
        if (mode === 'upload') {
            if (!chosen.some(c => !c.problem)) e.fileInput = 'Choose at least one file.';
            if (!$('integrity').checked) e.integrity = 'Confirm the academic integrity statement.';
        }
        return e;
    }

    function openUpload(course = '') {
        if (!data.canUpload) return;
        mode = 'upload';
        editTarget = null;
        chosen = [];
        form.el.reset();
        delete form.fields.description.dataset.edited;
        clearErrors();
        renderPicked();
        form.title.textContent = 'Upload notes';
        form.drop.hidden = false;
        form.integrity.hidden = false;
        form.note.hidden = false;
        form.editing.hidden = true;
        form.status.textContent = '';
        form.progress.hidden = true;
        form.submit.textContent = 'Upload';
        // Start from the course being browsed and the current term.
        form.fields.classCode.value = course || els.course.value || '';
        if (data.term) { form.fields.semester.value = data.term.semester; form.fields.year.value = data.term.year; }
        form.fields.category.value = 'Lecture Notes';
        form.dlg.showModal();
        form.picker.refresh();
        form.fields.classCode.value ? form.fields.professor.focus() : form.fields.classCode.focus();
    }

    function openEdit(f) {
        mode = 'edit';
        editTarget = f;
        form.el.reset();
        clearErrors();
        form.title.textContent = 'Edit details';
        form.drop.hidden = true;
        form.integrity.hidden = true;
        form.note.hidden = true;
        form.editing.hidden = false;
        form.editing.textContent = f.name;
        form.status.textContent = '';
        form.progress.hidden = true;
        for (const k of Object.keys(form.fields)) form.fields[k].value = f[k] || '';
        if (f.year && ![...form.fields.year.options].some(o => o.value === f.year)) form.fields.year.add(new Option(f.year, f.year));
        if (!CATEGORIES.includes(f.category)) form.fields.category.add(new Option(f.category, f.category));
        form.fields.category.value = f.category;
        form.fields.description.dataset.edited = '1';
        form.submit.textContent = 'Save';
        form.dlg.showModal();
        form.picker.refresh();
    }

    async function sha256(file) {
        const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
        return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function put(url, file, type, onProgress) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('PUT', url);
            xhr.setRequestHeader('Content-Type', type);
            xhr.upload.onprogress = e => e.lengthComputable && onProgress(e.loaded / e.total);
            xhr.onload = () => (xhr.status >= 200 && xhr.status < 300 ? resolve() : reject(new Error(`Storage rejected the upload (${xhr.status}).`)));
            xhr.onerror = () => reject(new Error('Network error while uploading.'));
            xhr.send(file);
        });
    }

    async function postJson(url, body) {
        const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const json = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(json.error || `Request failed (${res.status}).`);
        return json;
    }

    async function uploadAll(v) {
        const queue = chosen.filter(c => !c.problem).map(c => c.file);
        const bar = form.progress.firstElementChild;
        form.progress.hidden = false;
        const result = { uploaded: 0, duplicates: 0, held: [], failed: [] };
        for (let i = 0; i < queue.length; i++) {
            const file = queue[i];
            const type = file.type || 'application/octet-stream';
            const step = p => { bar.style.width = `${Math.round(((i + p) / queue.length) * 100)}%`; };
            form.status.textContent = `Uploading ${file.name} (${i + 1} of ${queue.length})…`;
            try {
                step(0);
                const fileHash = await sha256(file);
                const { uploadUrl, s3Key, s3Url } = await postJson('/api/get-upload-url', { filename: file.name, filetype: type, filesize: file.size });
                await put(uploadUrl, file, type, p => step(p * 0.9));
                const r = await postJson('/api/confirm-upload', { s3Key, s3Url, filename: file.name, filetype: type, filesize: file.size, fileHash, ...v });
                if (r.duplicate) result.duplicates++;
                else result.uploaded++;
                if (r.held) result.held.push(file.name);
                step(1);
            } catch (err) {
                result.failed.push(`${file.name}: ${err.message}`);
            }
        }
        return result;
    }

    async function submitForm(e) {
        e.preventDefault();
        if (busy) return;
        clearErrors();
        const v = values();
        const errors = validate(v);
        if (Object.keys(errors).length) {
            if (errors.fileInput) form.status.textContent = errors.fileInput;
            return showErrors(errors);
        }
        busy = true;
        form.submit.disabled = true;
        try {
            if (mode === 'edit') {
                form.submit.textContent = 'Saving…';
                await postJson('/edit-file', { filename: editTarget.filename, ...v });
                Object.assign(editTarget, v, { term: `${v.semester} ${v.year}` });
                editTarget.haystack = [editTarget.name, v.description, v.classCode, v.professor, v.category, editTarget.uploadedBy, v.semester, v.year].join(' ').toLowerCase();
                form.dlg.close();
                buildFilters();
                render();
                toast('Saved.', 'success');
            } else {
                form.submit.textContent = 'Uploading…';
                const r = await uploadAll(v);
                const parts = [];
                if (r.uploaded) parts.push(`Uploaded ${r.uploaded} ${r.uploaded === 1 ? 'file' : 'files'} to ${v.classCode}.`);
                if (r.duplicates) parts.push(`${r.duplicates} already shared for this class and term, so skipped.`);
                if (r.held.length) parts.push(`${r.held.join(', ')} may contain personal information; an admin will review before others can see ${r.held.length === 1 ? 'it' : 'them'}.`);
                if (r.failed.length) {
                    form.status.textContent = `Couldn't upload: ${r.failed.join('; ')}`;
                    if (r.uploaded) toast(parts.join(' '), 'success', 8000);
                } else {
                    form.status.textContent = parts.join(' ');
                    toast(parts.join(' ') || 'Done.', 'success', 8000);
                    // Show the new notes, filtered to their course.
                    setTimeout(() => { location.href = `/dashboard?course=${encodeURIComponent(v.classCode)}`; }, r.held.length ? 2500 : 900);
                }
            }
        } catch (err) {
            form.status.textContent = err.message;
            toast(err.message, 'error');
        } finally {
            busy = false;
            form.submit.disabled = false;
            if (mode === 'edit') form.submit.textContent = 'Save';
            else renderPicked();
        }
    }

    // ---------- report ----------

    let reportTarget = null;
    function openReport(f) {
        reportTarget = f;
        $('reportName').textContent = f.name;
        $('reportForm').reset();
        $('reportDialog').showModal();
    }

    async function sendReport(e) {
        e.preventDefault();
        const reason = $('reportForm').querySelector('input[name="reason"]:checked')?.value;
        try {
            await postJson('/api/report-file', { filename: reportTarget.filename, originalName: reportTarget.name, reason, details: $('reportDetails').value.trim() });
            $('reportDialog').close();
            toast('Thanks. An admin will review it.', 'success');
        } catch (err) {
            toast(err.message, 'error');
        }
    }

    // ---------- events ----------

    function closeMenus(except) {
        document.querySelectorAll('details.tn-menu[open]').forEach(d => { if (d !== except) d.removeAttribute('open'); });
    }

    let typing;
    els.q.addEventListener('input', () => { clearTimeout(typing); typing = setTimeout(rerender, 120); });
    for (const el of [els.category, els.term, els.professor, els.sort, els.mine]) el.addEventListener('change', rerender);
    els.course.addEventListener('change', () => { refreshProfessors(); rerender(); });
    els.clear.addEventListener('click', clearAll);
    function clearAll() {
        els.q.value = '';
        for (const el of [els.course, els.category, els.term, els.professor]) el.value = '';
        els.mine.checked = false;
        refreshProfessors();
        rerender();
    }
    els.filtersToggle.addEventListener('click', () => {
        const open = els.filters.classList.toggle('is-open');
        els.filtersToggle.setAttribute('aria-expanded', String(open));
    });
    els.more.addEventListener('click', () => { state.shown += PAGE; render(); });
    els.selectToggle.addEventListener('click', () => setSelecting(!state.selecting));
    els.bulkCancel.addEventListener('click', () => setSelecting(false));
    els.bulkDownload.addEventListener('click', bulkDownload);
    els.bulkDelete.addEventListener('click', () => deleteFiles([...state.selected]));

    document.addEventListener('click', async e => {
        const t = e.target;
        if (t.closest('[data-open-upload]')) {
            e.preventDefault(); // the tab bar's upload button is a link to /dashboard#upload
            return openUpload(t.closest('[data-open-upload]').dataset.course || '');
        }
        if (t.closest('[data-clear]')) return clearAll();
        const chip = t.closest('.tn-chip[data-course]');
        if (chip) {
            els.course.value = chip.dataset.course;
            refreshProfessors();
            rerender();
            return window.scrollTo({ top: 0, behavior: 'smooth' });
        }
        const menu = t.closest('details.tn-menu');
        closeMenus(menu);
        const action = t.closest('[data-action]');
        if (action) {
            const f = byName.get(action.closest('.tn-file').dataset.filename);
            action.closest('details').removeAttribute('open');
            if (action.dataset.action === 'edit') openEdit(f);
            if (action.dataset.action === 'report') openReport(f);
            if (action.dataset.action === 'delete') deleteFiles([f.filename]);
            if (action.dataset.action === 'buddy') studyWith([f]);
            if (action.dataset.action === 'copy') {
                const url = new URL(`/download/${encodeURIComponent(f.filename)}`, location.origin).href;
                try { await navigator.clipboard.writeText(url); toast('Link copied. Classmates need to sign in to open it.', 'success'); }
                catch { toast(url, 'info', 8000); }
            }
            return;
        }
        // In select mode, tapping a row toggles it (links and buttons keep working).
        const li = t.closest('.tn-file');
        // A click on the checkbox's label is followed by one on the checkbox itself: count it once.
        if (li && state.selecting && t.closest('.tn-file-check') && t.tagName !== 'INPUT') return;
        if (li && state.selecting && !t.closest('a, button, summary, details')) {
            const fn = li.dataset.filename;
            state.selected.has(fn) ? state.selected.delete(fn) : state.selected.add(fn);
            const box = li.querySelector('[data-select]');
            if (box && t !== box) box.checked = state.selected.has(fn);
            li.classList.toggle('is-selected', state.selected.has(fn));
            updateSelectBar();
        }
        if (t.closest('[data-close]')) t.closest('dialog').close();
        if (t.closest('[data-dismiss]')) {
            const box = t.closest('[data-announcement]');
            try { localStorage.setItem(`tn-dismissed-${box.dataset.announcement}`, '1'); } catch {}
            box.remove();
        }
        const remove = t.closest('[data-remove]');
        if (remove) { chosen.splice(Number(remove.dataset.remove), 1); renderPicked(); }
    });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeMenus(); });

    $('uploadOpen')?.addEventListener('click', () => openUpload());
    $('bulkBuddy')?.addEventListener('click', () => {
        const picked = [...state.selected].map(fn => byName.get(fn)).filter(Boolean);
        setSelecting(false);
        studyWith(picked);
    });
    $('pinCourse')?.addEventListener('click', async () => {
        const course = els.course.value;
        if (!course || !window.TerpShell) return;
        const on = window.TerpShell.pinned().includes(course);
        try {
            await window.TerpShell.setPinned(course, !on);
            toast(on ? `Removed ${course} from My courses.` : `Added ${course} to My courses.`, 'success');
        } catch (err) {
            toast(err.message, 'error');
        }
    });
    document.addEventListener('terp:pinned', updatePin);
    // The sidebar's search box filters this list in place, without reloading the page.
    document.querySelector('.tn-side-search')?.addEventListener('submit', e => {
        e.preventDefault();
        els.q.value = e.target.elements.q.value.trim().slice(0, 100);
        e.target.elements.q.value = '';
        window.TerpShell?.closeDrawer();
        rerender();
        els.q.focus();
    });
    form.input.addEventListener('change', () => { addFiles(form.input.files); form.input.value = ''; });
    form.fields.description.addEventListener('input', () => { form.fields.description.dataset.edited = '1'; });
    for (const evt of ['dragenter', 'dragover']) form.drop.addEventListener(evt, e => { e.preventDefault(); form.drop.classList.add('is-over'); });
    for (const evt of ['dragleave', 'drop']) form.drop.addEventListener(evt, e => { e.preventDefault(); form.drop.classList.remove('is-over'); });
    form.drop.addEventListener('drop', e => addFiles(e.dataTransfer.files));
    form.el.addEventListener('submit', submitForm);
    form.dlg.addEventListener('cancel', e => { if (busy) e.preventDefault(); });
    $('reportForm').addEventListener('submit', sendReport);
    // A click on the backdrop closes a dialog.
    for (const dlg of document.querySelectorAll('dialog.tn-dialog')) {
        dlg.addEventListener('click', e => { if (e.target === dlg && !busy) dlg.close(dlg.id === 'confirmDialog' ? 'cancel' : ''); });
    }

    // Announcements dismissed before stay hidden.
    document.querySelectorAll('[data-announcement]').forEach(box => {
        try { if (localStorage.getItem(`tn-dismissed-${box.dataset.announcement}`)) box.remove(); } catch {}
    });

    buildFilters();
    readUrl();
    render();
    if (location.hash === '#upload') openUpload();
})();
