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
    const tabCourses = $('tabCourses');
    if (tabCourses) {
        tabCourses.addEventListener('click', () => {
            setDrawer(true);
            const first = side.querySelector('.tn-side-course') || side.querySelector('#sideAddCourse input');
            if (first) first.focus({ preventScroll: true });
        });
    }
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && document.body.classList.contains('side-open')) setDrawer(false);
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
        side.querySelectorAll('[data-course-link]').forEach((a) => set(a, a.dataset.courseLink === course));
        set(side.querySelector('[data-nav="mine"]'), mine && !course);
        set(side.querySelector('[data-nav="notes"]'), onNotes && !mine && !course);
    }
    markActive();

    // ---------- My courses ----------

    const list = $('sideCourses');
    const empty = $('sideCoursesEmpty');
    const addForm = $('sideAddCourse');
    const addError = $('sideAddError');
    let pinned = [...list.querySelectorAll('[data-course-link]')].map((a) => a.dataset.courseLink);

    function renderPinned() {
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
            remove.textContent = '×';
            a.append(dot, name);
            li.append(a, remove);
            list.appendChild(li);
        }
        empty.hidden = pinned.length > 0;
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

    addForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const input = addForm.elements.classCode;
        const code = input.value.toUpperCase().replace(/\s+/g, '');
        addError.hidden = true;
        if (!COURSE_CODE.test(code)) {
            addError.textContent = 'Use a class code like CMSC330.';
            addError.hidden = false;
            return;
        }
        try {
            await setPinned(code, true);
            input.value = '';
        } catch (err) {
            addError.textContent = err.message;
            addError.hidden = false;
        }
    });

    list.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-unpin]');
        if (!btn) return;
        e.preventDefault();
        setPinned(btn.dataset.unpin, false).catch((err) => {
            addError.textContent = err.message;
            addError.hidden = false;
        });
    });

    renderPinned();

    // Other scripts (the notes list) pin and unpin through this.
    window.TerpShell = {
        pinned: () => pinned.slice(),
        setPinned,
        markActive,
        closeDrawer: () => setDrawer(false),
    };
})();
