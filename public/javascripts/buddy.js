// Study Buddy panel. Opens over any signed-in page; the chat, the chosen course and the chosen
// files are kept for the browser tab, so moving between pages doesn't lose them.
(function () {
    const $ = (id) => document.getElementById(id);
    const panel = $('buddyPanel');
    if (!panel) return;

    const els = {
        launch: $('buddyLaunch'), close: $('buddyClose'), fresh: $('buddyNew'), course: $('buddyCourse'),
        filesBtn: $('buddyFilesBtn'), files: $('buddyFiles'), fileList: $('buddyFileList'), chips: $('buddyChips'),
        thread: $('buddyThread'), make: $('buddyMake'), form: $('buddyForm'), question: $('buddyQuestion'), send: $('buddySend'),
    };
    const aiEnabled = panel.dataset.ai === '1';
    const STORE = 'tn.buddy.v1';
    const MAX_FILES = 20;
    const KIND_LABEL = { quiz: 'Quiz', cheatsheet: 'Cheat sheet', exam: 'Practice exam', flashcards: 'Flashcards', summary: 'Summary' };
    const REQUEST_LABEL = {
        quiz: 'Quiz me', cheatsheet: 'Make a cheat sheet', exam: 'Write a practice exam', flashcards: 'Make flashcards', summary: 'Summarize',
    };

    // ---------- state ----------

    const state = { open: false, course: '', files: [], thread: [] };
    try {
        Object.assign(state, JSON.parse(sessionStorage.getItem(STORE) || '{}'));
    } catch (e) { /* private mode or bad data: start fresh */ }
    if (!Array.isArray(state.files)) state.files = [];
    if (!Array.isArray(state.thread)) state.thread = [];

    function save() {
        try {
            sessionStorage.setItem(STORE, JSON.stringify({ ...state, thread: state.thread.slice(-30) }));
        } catch (e) { /* storage full or blocked: the chat still works for this page */ }
    }

    let courses = null; // loaded the first time the panel opens
    let courseFiles = [];
    let busy = false;

    // ---------- small helpers ----------

    const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    // A small, safe subset of Markdown: everything is escaped first, then headings, lists,
    // bold and inline code are turned into tags. Nothing from the model reaches the page as HTML.
    function markdown(text) {
        const inline = (s) => esc(s)
            .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/\[(\d{1,2})\]/g, '<sup class="tn-cite">$1</sup>');
        const out = [];
        let list = null;
        const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
        for (const raw of String(text).replace(/\r/g, '').split('\n')) {
            const line = raw.trimEnd();
            const heading = /^(#{1,4})\s+(.*)$/.exec(line);
            const bullet = /^\s*[-*•]\s+(.*)$/.exec(line);
            const numbered = /^\s*(\d{1,2})[.)]\s+(.*)$/.exec(line);
            if (heading) {
                closeList();
                out.push(`<h4>${inline(heading[2])}</h4>`);
            } else if (bullet) {
                if (list !== 'ul') { closeList(); out.push('<ul>'); list = 'ul'; }
                out.push(`<li>${inline(bullet[1])}</li>`);
            } else if (numbered) {
                if (list !== 'ol') { closeList(); out.push(`<ol start="${Number(numbered[1])}">`); list = 'ol'; }
                out.push(`<li>${inline(numbered[2])}</li>`);
            } else if (!line.trim()) {
                closeList();
            } else {
                closeList();
                out.push(`<p>${inline(line)}</p>`);
            }
        }
        closeList();
        return out.join('');
    }

    async function getJson(url, options) {
        const res = await fetch(url, options);
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || (res.status === 401 ? 'Please sign in again.' : 'Something went wrong.'));
        return body;
    }

    // ---------- context: course and files ----------

    function fillCourses() {
        const keep = state.course;
        els.course.length = 1;
        for (const c of courses || []) els.course.add(new Option(c, c));
        if (keep && !(courses || []).includes(keep)) els.course.add(new Option(keep, keep));
        els.course.value = keep || '';
    }

    function renderContext() {
        const n = state.files.length;
        els.filesBtn.disabled = !state.course;
        els.filesBtn.textContent = n ? `${n} ${n === 1 ? 'file' : 'files'}` : 'All notes';
        els.chips.textContent = '';
        for (const f of state.files) {
            const chip = document.createElement('span');
            chip.className = 'tn-buddy-chip';
            const name = document.createElement('span');
            name.textContent = f.name;
            const x = document.createElement('button');
            x.type = 'button';
            x.setAttribute('aria-label', `Stop using ${f.name}`);
            x.dataset.drop = f.filename;
            x.textContent = '×';
            chip.append(name, x);
            els.chips.appendChild(chip);
        }
        els.fileList.querySelectorAll('input').forEach((box) => {
            box.checked = state.files.some((f) => f.filename === box.value);
        });
    }

    function renderFileList() {
        els.fileList.textContent = '';
        if (!courseFiles.length) {
            const li = document.createElement('li');
            li.className = 'tn-buddy-files-none';
            li.textContent = state.course ? `No readable notes for ${state.course} yet. The buddy reads text, PDF and Word files.` : 'Pick a course first.';
            els.fileList.appendChild(li);
            return;
        }
        for (const f of courseFiles) {
            const li = document.createElement('li');
            const label = document.createElement('label');
            const box = document.createElement('input');
            box.type = 'checkbox';
            box.value = f.filename;
            box.dataset.name = f.name;
            const text = document.createElement('span');
            text.textContent = f.name;
            label.append(box, text);
            if (f.category) {
                const cat = document.createElement('small');
                cat.textContent = f.category;
                label.appendChild(cat);
            }
            li.appendChild(label);
            els.fileList.appendChild(li);
        }
        renderContext();
    }

    async function loadCourseFiles() {
        courseFiles = [];
        if (state.course) {
            try {
                courseFiles = (await getJson(`/api/study/context?course=${encodeURIComponent(state.course)}`)).files || [];
            } catch (e) { /* the list stays empty; asking still works on the whole course */ }
        }
        renderFileList();
    }

    async function ensureCourses() {
        if (courses) return;
        try {
            courses = (await getJson('/api/study/context')).courses || [];
        } catch (e) {
            courses = [];
        }
        // On the notes list, start from the course being browsed.
        if (!state.course && location.pathname === '/dashboard') {
            const browsing = (new URLSearchParams(location.search).get('course') || '').toUpperCase();
            if (courses.includes(browsing)) state.course = browsing;
        }
        fillCourses();
        await loadCourseFiles();
        renderThread();
    }

    function setCourse(course, keepFiles) {
        state.course = course || '';
        if (!keepFiles) state.files = [];
        if (els.course.value !== state.course) {
            if (state.course && ![...els.course.options].some((o) => o.value === state.course)) els.course.add(new Option(state.course, state.course));
            els.course.value = state.course;
        }
        els.files.hidden = true;
        els.filesBtn.setAttribute('aria-expanded', 'false');
        save();
        renderContext();
        return loadCourseFiles();
    }

    // ---------- thread ----------

    function emptyThread() {
        const box = document.createElement('div');
        box.className = 'tn-buddy-empty';
        const h = document.createElement('h3');
        const p = document.createElement('p');
        if (courses && !courses.length) {
            h.textContent = 'No notes to study from yet';
            p.textContent = 'Once someone uploads text, PDF or Word notes for a course, the buddy can answer questions about them.';
        } else if (!state.course && !state.files.length) {
            h.textContent = 'Pick a course to start';
            p.textContent = 'Then ask a question, or tap a button below to get a cheat sheet, a practice exam, a quiz, flashcards or a summary.';
        } else {
            h.textContent = `Ready for ${state.files.length ? (state.files.length === 1 ? state.files[0].name : `${state.files.length} files`) : state.course}`;
            p.textContent = aiEnabled
                ? 'Ask anything, or tap a button below. Add a topic first to focus it, like "recursion" then Quiz me.'
                : "AI answers aren't switched on yet, so you'll get the most relevant passages from the notes.";
        }
        box.append(h, p);
        return box;
    }

    function buddyBubble(turn) {
        const div = document.createElement('div');
        div.className = 'msg buddy';
        if (turn.pending) {
            div.classList.add('is-pending');
            div.textContent = turn.kind && turn.kind !== 'ask' ? `Writing your ${(KIND_LABEL[turn.kind] || 'answer').toLowerCase()}…` : 'Thinking…';
            return div;
        }
        if (turn.error) {
            div.classList.add('is-error');
            div.textContent = turn.text;
            return div;
        }
        const badge = document.createElement('span');
        badge.className = `badge ${turn.mode === 'ai' ? 'ai' : 'search'}`;
        badge.textContent = turn.mode === 'ai' ? (turn.kind && turn.kind !== 'ask' ? `${KIND_LABEL[turn.kind]} · AI` : 'AI answer') : 'From your class notes';
        const body = document.createElement('div');
        body.className = 'tn-buddy-answer';
        body.innerHTML = markdown(turn.text);
        div.append(badge, body);

        if (turn.sources && turn.sources.length) {
            const details = document.createElement('details');
            details.className = 'sources';
            // Without AI the passages are the answer, so they start open.
            details.open = turn.mode !== 'ai';
            const summary = document.createElement('summary');
            summary.textContent = `${turn.sources.length} ${turn.sources.length === 1 ? 'source' : 'sources'}`;
            details.appendChild(summary);
            for (const s of turn.sources) {
                const item = document.createElement('div');
                item.className = 'source';
                const link = document.createElement('a');
                link.href = `/download/${encodeURIComponent(s.filename)}`;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.textContent = `[${s.n}] ${s.originalName}`;
                const snip = document.createElement('p');
                snip.textContent = s.snippet;
                item.append(link, snip);
                details.appendChild(item);
            }
            div.appendChild(details);
        }

        if (turn.mode === 'ai') {
            const actions = document.createElement('div');
            actions.className = 'tn-buddy-actions';
            const copy = document.createElement('button');
            copy.type = 'button';
            copy.textContent = 'Copy';
            copy.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(turn.text);
                    copy.textContent = 'Copied';
                } catch (e) {
                    copy.textContent = "Couldn't copy";
                }
                setTimeout(() => { copy.textContent = 'Copy'; }, 1500);
            });
            actions.appendChild(copy);
            if (turn.kind && turn.kind !== 'ask') {
                const dl = document.createElement('button');
                dl.type = 'button';
                dl.textContent = 'Download';
                dl.addEventListener('click', () => {
                    const name = `${(turn.course || 'notes').toLowerCase()}-${turn.kind}.md`;
                    const url = URL.createObjectURL(new Blob([turn.text], { type: 'text/markdown' }));
                    const a = Object.assign(document.createElement('a'), { href: url, download: name });
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    setTimeout(() => URL.revokeObjectURL(url), 5000);
                });
                actions.appendChild(dl);
            }
            div.appendChild(actions);
        }
        return div;
    }

    function renderThread() {
        els.thread.textContent = '';
        if (!state.thread.length) {
            els.thread.appendChild(emptyThread());
            return;
        }
        for (const turn of state.thread) {
            if (turn.role === 'you') {
                const div = document.createElement('div');
                div.className = 'msg you';
                div.textContent = turn.text;
                els.thread.appendChild(div);
            } else {
                els.thread.appendChild(buddyBubble(turn));
            }
        }
        els.thread.scrollTop = els.thread.scrollHeight;
    }

    // Earlier question-and-answer turns, so "what about the second one?" makes sense to the model.
    function earlierTurns() {
        const turns = [];
        for (const t of state.thread) {
            if (t.pending || t.error) continue;
            if (t.role === 'you') turns.push({ role: 'user', content: t.text });
            else if (t.mode === 'ai') turns.push({ role: 'assistant', content: t.text });
        }
        return turns.slice(-6);
    }

    async function ask(mode) {
        if (busy) return;
        const question = els.question.value.trim();
        const say = (text) => { state.thread.push({ role: 'buddy', error: true, text }); renderThread(); };
        if (!state.course && !state.files.length) return say('Pick a course first.');
        if (mode === 'ask' && question.length < 3) return say('Type a question first.');

        const earlier = earlierTurns();
        const label = mode === 'ask' ? question : `${REQUEST_LABEL[mode]}${question ? `: ${question}` : state.course ? ` for ${state.course}` : ''}`;
        state.thread.push({ role: 'you', text: label });
        const pending = { role: 'buddy', pending: true, kind: mode };
        state.thread.push(pending);
        els.question.value = '';
        autosize();
        renderThread();

        busy = true;
        els.send.disabled = true;
        els.make.querySelectorAll('button').forEach((b) => { b.disabled = true; });
        try {
            const data = await getJson('/api/study/ask', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    classCode: state.course, question, mode,
                    files: state.files.map((f) => f.filename),
                    history: mode === 'ask' ? earlier : [],
                }),
            });
            Object.assign(pending, { pending: false, mode: data.mode, kind: data.kind || mode, text: data.answer, sources: data.sources || [], course: state.course });
        } catch (err) {
            Object.assign(pending, { pending: false, error: true, text: err.message });
        } finally {
            busy = false;
            els.send.disabled = false;
            els.make.querySelectorAll('button').forEach((b) => { b.disabled = false; });
            save();
            renderThread();
        }
    }

    // ---------- open and close ----------

    function setOpen(open, focus = true) {
        state.open = open;
        panel.hidden = !open;
        els.launch.setAttribute('aria-expanded', String(open));
        document.body.classList.toggle('buddy-open', open);
        save();
        if (open) {
            renderThread();
            ensureCourses();
            if (focus && !window.matchMedia('(max-width: 899px)').matches) els.question.focus({ preventScroll: true });
        } else if (focus) {
            els.launch.focus({ preventScroll: true });
        }
    }

    function autosize() {
        els.question.style.height = 'auto';
        els.question.style.height = `${Math.min(els.question.scrollHeight, 140)}px`;
    }

    // ---------- events ----------

    els.launch.addEventListener('click', () => setOpen(panel.hidden));
    els.close.addEventListener('click', () => setOpen(false));
    document.addEventListener('click', (e) => {
        const opener = e.target.closest('[data-buddy-open]');
        if (!opener) return;
        e.preventDefault();
        if (window.TerpShell) window.TerpShell.closeDrawer();
        setOpen(true);
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !panel.hidden && panel.contains(document.activeElement)) setOpen(false);
    });

    els.fresh.addEventListener('click', () => {
        state.thread = [];
        save();
        renderThread();
        els.question.focus();
    });

    els.course.addEventListener('change', () => { setCourse(els.course.value).then(renderThread); });

    els.filesBtn.addEventListener('click', () => {
        const show = els.files.hidden;
        els.files.hidden = !show;
        els.filesBtn.setAttribute('aria-expanded', String(show));
    });

    els.fileList.addEventListener('change', (e) => {
        const box = e.target;
        if (box.checked) {
            if (state.files.length >= MAX_FILES) { box.checked = false; return; }
            state.files.push({ filename: box.value, name: box.dataset.name });
        } else {
            state.files = state.files.filter((f) => f.filename !== box.value);
        }
        save();
        renderContext();
        if (!state.thread.length) renderThread();
    });

    els.chips.addEventListener('click', (e) => {
        const drop = e.target.closest('[data-drop]');
        if (!drop) return;
        state.files = state.files.filter((f) => f.filename !== drop.dataset.drop);
        save();
        renderContext();
        if (!state.thread.length) renderThread();
    });

    els.make.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-mode]');
        if (btn) ask(btn.dataset.mode);
    });

    els.form.addEventListener('submit', (e) => { e.preventDefault(); ask('ask'); });
    els.question.addEventListener('input', autosize);
    els.question.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
            e.preventDefault();
            ask('ask');
        }
    });

    // ---------- start ----------

    fillCourses();
    renderContext();
    const params = new URLSearchParams(location.search);
    if (params.get('buddy') === 'open') {
        // Arrived from an old /study link: open, and tidy the address.
        const course = (params.get('course') || '').toUpperCase();
        if (course && course !== state.course) { state.course = course; state.files = []; }
        params.delete('buddy');
        window.history.replaceState(null, '', `${location.pathname}${params.toString() ? `?${params}` : ''}${location.hash}`);
        setOpen(true, false);
    } else if (state.open) {
        setOpen(true, false);
    }

    // Other scripts hand the buddy a course or files: StudyBuddy.open({ course, files: [{ filename, name }] }).
    window.StudyBuddy = {
        async open({ course, files } = {}) {
            const picked = Array.isArray(files) ? files.filter((f) => f && f.filename).slice(0, MAX_FILES) : null;
            if (picked) state.files = picked.map((f) => ({ filename: f.filename, name: f.name || f.filename }));
            setOpen(true);
            await ensureCourses();
            if (course !== undefined && course !== state.course) await setCourse(course, Boolean(picked));
            else { save(); renderContext(); }
            renderThread();
        },
    };
})();
