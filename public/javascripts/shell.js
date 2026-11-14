// App shell: the sidebar (a slide-in drawer on phones), the bottom tab bar and "My courses".
(function () {
    const $ = (id) => document.getElementById(id);
    const side = $('tnSide');
    if (!side) return;
    const scrim = $('sideScrim');
    const openBtn = $('sideOpen');
    const phone = window.matchMedia('(max-width: 899px)');
    const COURSE_CODE = /^[A-Z]{2,5}\d{3}[A-Z]{0,2}$/;

    // ---------- drawer (phones and small tablets) ----------

    function setDrawer(open) {
        document.body.classList.toggle('side-open', open);
        scrim.hidden = !open;
        openBtn.setAttribute('aria-expanded', String(open));
        // Closed and off-screen, the drawer must not take keyboard focus.
        side.inert = phone.matches && !open;
        if (open) side.querySelector('a, button, input').focus({ preventScroll: true });
    }
    setDrawer(false);
    phone.addEventListener('change', () => setDrawer(false));
    openBtn.addEventListener('click', () => setDrawer(true));
    $('sideClose').addEventListener('click', () => setDrawer(false));
    scrim.addEventListener('click', () => setDrawer(false));
    // ---------- My courses sheet (phones): opens from the bottom, above the tab that opened it ----------

    const sheet = $('coursesSheet');
    const tabCourses = $('tabCourses');
    function setSheet(open) {
        if (!sheet) return;
        sheet.hidden = !open;
        document.body.classList.toggle('sheet-open', open);
        tabCourses.setAttribute('aria-expanded', String(open));
        scrim.hidden = !open && !document.body.classList.contains('side-open');
        if (open) sheet.focus({ preventScroll: true });
        else if (document.activeElement && sheet.contains(document.activeElement)) tabCourses.focus({ preventScroll: true });
    }
    if (sheet) {
        tabCourses.addEventListener('click', () => setSheet(sheet.hidden));
        $('coursesSheetClose').addEventListener('click', () => setSheet(false));
        scrim.addEventListener('click', () => setSheet(false));
        sheet.addEventListener('click', (e) => { if (e.target.closest('a')) setSheet(false); });
        phone.addEventListener('change', () => setSheet(false));
        // Opening the buddy or the upload form from the tab bar puts the sheet away first.
        document.addEventListener('click', (e) => {
            if (!sheet.hidden && e.target.closest('.tn-tabbar') && !e.target.closest('#tabCourses')) setSheet(false);
        }, true);
    }
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (document.body.classList.contains('side-open')) setDrawer(false);
        if (sheet && !sheet.hidden) setSheet(false);
    });
    side.addEventListener('click', (e) => {
        if (e.target.closest('a') && phone.matches) setDrawer(false);
    });

    // ---------- which link is "here" ----------

    function markActive() {
        const params = new URLSearchParams(location.search);
        const onNotes = location.pathname === '/dashboard';
        const course = onNotes ? (params.get('course') || '').toUpperCase() : '';
        const mine = onNotes && params.get('mine') === '1';
        const set = (el, on) => {
            if (!el) return;
            el.classList.toggle('is-active', on);
            if (on) el.setAttribute('aria-current', 'page');
            else el.removeAttribute('aria-current');
        };
        document.querySelectorAll('[data-course-link]').forEach((a) => set(a, a.dataset.courseLink === course));
        set(side.querySelector('[data-nav="mine"]'), mine && !course);
        set(side.querySelector('[data-nav="notes"]'), onNotes && !mine && !course);
    }
    markActive();

    // ---------- My courses ----------

    // The same list shows in the sidebar and in the phone sheet.
    const lists = [...document.querySelectorAll('[data-courses-list]')];
    const empties = [...document.querySelectorAll('[data-courses-empty]')];
    let pinned = [...$('sideCourses').querySelectorAll('[data-course-link]')].map((a) => a.dataset.courseLink);

    function renderPinned() {
        for (const list of lists) {
            list.textContent = '';
            for (const code of pinned) {
                const li = document.createElement('li');
                const a = document.createElement('a');
                a.href = `/dashboard?course=${encodeURIComponent(code)}`;
                a.className = 'tn-side-link tn-side-course';
                a.dataset.courseLink = code;
                const dot = document.createElement('span');
                dot.className = 'tn-course-dot';
                dot.setAttribute('aria-hidden', 'true');
                const name = document.createElement('span');
                name.textContent = code;
                const remove = document.createElement('button');
                remove.type = 'button';
                remove.className = 'tn-side-remove';
                remove.setAttribute('aria-label', `Remove ${code} from My courses`);
                remove.dataset.unpin = code;
                remove.textContent = '\u00d7';
                a.append(dot, name);
                li.append(a, remove);
                list.appendChild(li);
            }
        }
        for (const empty of empties) empty.hidden = pinned.length > 0;
        markActive();
        document.dispatchEvent(new CustomEvent('terp:pinned', { detail: pinned.slice() }));
    }

    async function setPinned(classCode, on) {
        const res = await fetch('/api/courses/pin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ classCode, pinned: on }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || 'Could not update your courses.');
        pinned = body.pinnedCourses || [];
        renderPinned();
        return pinned;
    }

    for (const addForm of document.querySelectorAll('[data-add-course]')) {
        const addError = addForm.parentElement.querySelector('[data-add-error]');
        const fail = (message) => { addError.textContent = message; addError.hidden = false; };
        addForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = addForm.elements.classCode;
            const code = input.value.toUpperCase().replace(/\s+/g, '');
            addError.hidden = true;
            if (!COURSE_CODE.test(code)) return fail('Use a class code like CMSC330.');
            try {
                await setPinned(code, true);
                input.value = '';
            } catch (err) {
                fail(err.message);
            }
        });
    }

    for (const list of lists) {
        list.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-unpin]');
            if (!btn) return;
            e.preventDefault();
            e.stopPropagation();
            setPinned(btn.dataset.unpin, false).catch(() => {});
        });
    }

    renderPinned();

    // Other scripts (the notes list) pin and unpin through this.
    window.TerpShell = {
        pinned: () => pinned.slice(),
        setPinned,
        markActive,
        closeDrawer: () => setDrawer(false),
    };
})();
