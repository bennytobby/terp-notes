// Course and professor fields with suggestions from the UMD catalog (/api/course-suggest).
// Shared by the dashboard's upload and edit forms and the integrations import form, so every
// way of adding a note asks for class details the same way.
(function () {
    const COURSE_CODE = /^[A-Z]{2,5}\d{3}[A-Z]?$/;

    function esc(value) {
        return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    function debounce(fn, ms) {
        let timer;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => fn(...args), ms);
        };
    }

    /** A small accessible autocomplete: arrow keys, Enter to pick, Escape to close. */
    function combobox(input, list, { onInput, onPick, onFocus }) {
        let items = [];
        let active = -1;
        const close = () => {
            list.hidden = true;
            input.setAttribute('aria-expanded', 'false');
            input.removeAttribute('aria-activedescendant');
            active = -1;
        };
        const highlight = i => {
            active = i;
            [...list.children].forEach((li, n) => li.setAttribute('aria-selected', String(n === i)));
            if (i >= 0) {
                list.children[i].scrollIntoView({ block: 'nearest' });
                input.setAttribute('aria-activedescendant', list.children[i].id);
            }
        };
        const combo = {
            show(next) {
                items = next;
                if (!items.length || document.activeElement !== input) return close();
                list.innerHTML = items.map((item, i) => `
                    <li id="${list.id}-${i}" role="option" aria-selected="false" data-i="${i}">
                        <span class="combo-main">${esc(item.label)}</span>${item.detail ? `<span class="combo-detail">${esc(item.detail)}</span>` : ''}
                    </li>`).join('');
                list.hidden = false;
                input.setAttribute('aria-expanded', 'true');
                active = -1;
            },
            close
        };
        input.addEventListener('input', () => onInput(input.value.trim()));
        if (onFocus) {
            input.addEventListener('focus', onFocus);
            input.addEventListener('click', () => { if (list.hidden) onFocus(); });
        }
        input.addEventListener('keydown', e => {
            if (list.hidden) return;
            if (e.key === 'ArrowDown') { e.preventDefault(); highlight(Math.min(active + 1, items.length - 1)); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); highlight(Math.max(active - 1, 0)); }
            else if (e.key === 'Enter' && active >= 0) { e.preventDefault(); const item = items[active]; close(); onPick(item); }
            else if (e.key === 'Escape') { e.stopPropagation(); close(); }
        });
        list.addEventListener('mousedown', e => {
            const li = e.target.closest('li[data-i]');
            if (!li) return;
            e.preventDefault();
            const item = items[Number(li.dataset.i)];
            close();
            onPick(item);
        });
        input.addEventListener('blur', () => setTimeout(close, 120));
        return combo;
    }

    /**
     * Wires a class-code input and a professor input. Elements: classInput, classList (ul),
     * profInput, profList (ul), courseInfo and profHelp (help text). `next` is focused after a
     * professor is picked.
     */
    function attach({ classInput, classList, profInput, profList, courseInfo, profHelp, hasCatalog, next }) {
        let professors = [];
        let lastCourse = '';
        const idleHelp = hasCatalog ? 'Start typing to search UMD courses.' : 'Your course code, e.g. CMSC330.';
        courseInfo.textContent = idleHelp;
        if (profHelp) profHelp.textContent = hasCatalog ? 'Pick a course to see who teaches it.' : '';
        let profCombo = null;

        const loadCourse = async code => {
            if (!hasCatalog || code === lastCourse) return;
            lastCourse = code;
            professors = [];
            if (!COURSE_CODE.test(code)) {
                courseInfo.textContent = idleHelp;
                courseInfo.classList.remove('ok');
                return;
            }
            try {
                const res = await fetch(`/api/course-suggest/${encodeURIComponent(code)}`, { credentials: 'include' });
                if (code !== lastCourse) return;
                if (!res.ok) {
                    courseInfo.textContent = "Not in the UMD catalog, but you can still use it.";
                    courseInfo.classList.remove('ok');
                    if (profHelp) profHelp.textContent = '';
                    return;
                }
                const course = await res.json();
                courseInfo.textContent = `${course.id}: ${course.name}`;
                courseInfo.classList.add('ok');
                professors = course.professors.map(p => ({
                    value: p.name,
                    label: p.name,
                    detail: p.terms.length ? `Taught ${p.terms.slice(0, 2).map(t => `${t.semester} ${t.year}`).join(', ')}` : ''
                }));
                if (profHelp) profHelp.textContent = professors.length ? `${professors.length} professor${professors.length === 1 ? '' : 's'} taught ${course.id}. Pick one or type a name.` : '';
                // Picking a course moves focus to the professor field before this arrives: open it now.
                if (profCombo && document.activeElement === profInput && !profInput.value) profCombo.show(professors.slice(0, 8));
            } catch {
                courseInfo.textContent = 'Course search is unavailable right now. You can still type the code.';
            }
        };

        if (hasCatalog) {
            let courseCombo = null;
            const searchCourses = debounce(async q => {
                if (q.length < 2) return courseCombo.show([]);
                try {
                    const res = await fetch(`/api/course-suggest?q=${encodeURIComponent(q)}`, { credentials: 'include' });
                    const data = await res.json();
                    if (classInput.value.trim().toUpperCase() === q) courseCombo.show((data.courses || []).map(c => ({ value: c.id, label: c.id, detail: c.name })));
                } catch {
                    courseCombo.show([]);
                }
            }, 150);
            courseCombo = combobox(classInput, classList, {
                onInput: q => searchCourses(q.toUpperCase().replace(/\s+/g, '')),
                onPick: item => { classInput.value = item.value; loadCourse(item.value); profInput.focus(); }
            });
            profCombo = combobox(profInput, profList, {
                onInput: q => {
                    const term = q.toLowerCase();
                    profCombo.show(professors.filter(p => !term || p.label.toLowerCase().includes(term)).slice(0, 8));
                },
                onFocus: () => profCombo.show(professors.slice(0, 8)),
                onPick: item => { profInput.value = item.value; next?.focus(); }
            });
        }

        classInput.addEventListener('input', () => {
            const caret = classInput.selectionStart;
            classInput.value = classInput.value.toUpperCase().replace(/\s+/g, '');
            classInput.setSelectionRange(caret, caret);
        });
        classInput.addEventListener('change', () => loadCourse(classInput.value.trim()));
        classInput.addEventListener('blur', () => setTimeout(() => loadCourse(classInput.value.trim()), 150));

        return {
            /** Shows the course name and professors for a code already in the field (edit form). */
            refresh: () => loadCourse(classInput.value.trim())
        };
    }

    window.CoursePicker = { attach, combobox, esc, COURSE_CODE };
})();
