// Admin page (views/admin.ejs): review queue, people, course staff, announcements and tools.
(function () {
    const $ = (id) => document.getElementById(id);
    const confirmBox = (message, title) => (window.customConfirm ? window.customConfirm(message, title) : Promise.resolve(window.confirm(message)));

    // ---------- small helpers ----------

    let toastTimer;
    function toast(message, type = 'success') {
        const el = $('admToast');
        el.textContent = message;
        el.classList.toggle('is-error', type === 'error');
        el.hidden = false;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
    }

    async function post(url, body) {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify(body || {}),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || data.message || `Request failed (${res.status})`);
        return data;
    }

    // Disables a button while its request runs, so a double tap can't send it twice.
    async function busy(btn, job) {
        if (btn) btn.disabled = true;
        try {
            return await job();
        } catch (err) {
            toast(err.message || 'Something went wrong.', 'error');
        } finally {
            if (btn && btn.isConnected) btn.disabled = false;
        }
    }

    const reloadSoon = () => setTimeout(() => window.location.reload(), 700);

    // ---------- dialogs ----------

    let lastFocus = null;
    function openModal(id) {
        lastFocus = document.activeElement;
        const modal = $(id);
        modal.hidden = false;
        document.body.classList.add('sheet-open');
        (modal.querySelector('textarea, select, input, button:not([data-close])') || modal.querySelector('button'))?.focus();
    }
    function closeModal(modal) {
        modal.hidden = true;
        if (!document.querySelector('.adm-modal:not([hidden])')) document.body.classList.remove('sheet-open');
        lastFocus?.focus?.();
    }
    document.querySelectorAll('.adm-modal').forEach((modal) => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.closest('[data-close]')) closeModal(modal);
        });
    });
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        const open = [...document.querySelectorAll('.adm-modal:not([hidden])')].pop();
        if (open) closeModal(open);
    });

    // ---------- review queue ----------

    function dropReviewItem(item) {
        item?.remove();
        const left = document.querySelectorAll('[data-review-list] .adm-item').length;
        document.querySelectorAll('[data-review-count]').forEach((el) => {
            el.textContent = left;
            el.classList.toggle('adm-count-alert', left > 0);
        });
        const jump = document.querySelector('.adm-jump a[href="#review"] .adm-count');
        if (jump) left ? (jump.textContent = left) : jump.remove();
        document.querySelector('[data-review-empty]').hidden = left > 0;
    }

    document.addEventListener('click', async (e) => {
        const conf = e.target.closest('[data-confidential]');
        if (conf) {
            const remove = conf.dataset.confidential === 'remove';
            if (!(await confirmBox(remove ? 'Remove this file for everyone?' : 'Approve this file and make it visible to students?', remove ? 'Remove file' : 'Approve file'))) return;
            await busy(conf, async () => {
                await post('/api/admin/confidential-review', { fileHash: conf.dataset.hash, action: conf.dataset.confidential });
                toast(remove ? 'File removed.' : 'File approved.');
                dropReviewItem(conf.closest('.adm-item'));
            });
            return;
        }
        const rep = e.target.closest('[data-report]');
        if (rep) {
            const del = rep.dataset.report === 'delete';
            if (!(await confirmBox(del ? 'Delete this file for everyone?' : 'Dismiss this report and keep the file?', del ? 'Delete file' : 'Dismiss report'))) return;
            await busy(rep, async () => {
                await post('/api/resolve-report', { reportId: rep.dataset.id, action: rep.dataset.report });
                toast(del ? 'File deleted.' : 'Report dismissed.');
                dropReviewItem(rep.closest('.adm-item'));
            });
        }
    });

    // ---------- people ----------

    const search = $('userSearch');
    const roleFilter = $('roleFilter');
    const cards = () => [...document.querySelectorAll('.user-card')];

    function filterUsers() {
        const term = search.value.trim().toLowerCase();
        const role = roleFilter.value;
        let shown = 0;
        for (const card of cards()) {
            const roleOk = !role || (role === 'banned' ? card.dataset.banned === '1' : card.dataset.role === role);
            const match = roleOk && (!term || card.dataset.search.includes(term));
            card.hidden = !match;
            if (match) shown++;
        }
        document.querySelector('[data-users-empty]').hidden = shown > 0;
    }
    search.addEventListener('input', filterUsers);
    roleFilter.addEventListener('change', filterUsers);

    function updateStatistics() {
        const all = cards();
        const count = (r) => all.filter((c) => c.dataset.role === r).length;
        $('totalUsers').textContent = all.length;
        $('adminCount').textContent = count('admin');
        $('contributorCount').textContent = count('contributor');
        $('viewerCount').textContent = count('viewer');
        document.querySelectorAll('[data-user-total]').forEach((el) => { el.textContent = all.length; });
    }

    const ROLE_LABEL = { admin: 'Admin', contributor: 'Contributor', viewer: 'Viewer' };

    // The Save button only wakes up once the role actually changes.
    document.querySelectorAll('.role-select').forEach((select) => {
        const card = select.closest('.user-card');
        select.addEventListener('change', () => {
            const save = card.querySelector('.update-role-btn');
            if (save) save.disabled = select.value === card.dataset.role;
        });
    });

    document.addEventListener('click', async (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        const card = btn.closest('.user-card');
        const userId = btn.dataset.userId;
        const userName = btn.dataset.userName;

        if (btn.classList.contains('update-role-btn')) {
            const newRole = $(`role-${userId}`).value;
            await busy(btn, async () => {
                await post('/api/update-user-role', { userId, newRole });
                card.dataset.role = newRole;
                const badge = card.querySelector('.user-role');
                badge.textContent = ROLE_LABEL[newRole] || newRole;
                badge.className = `tn-badge adm-role user-role role-${newRole}`;
                updateStatistics();
                toast(`${userName || userId} is now ${ROLE_LABEL[newRole] || newRole}.`);
            });
            btn.disabled = true;
        } else if (btn.classList.contains('delete-btn')) {
            if (!(await confirmBox(`Delete ${userName}'s account and all of their files? This can't be undone.`, 'Delete user'))) return;
            await busy(btn, async () => {
                await post('/api/delete-user', { userId });
                card.remove();
                updateStatistics();
                filterUsers();
                toast('Account deleted.');
            });
        } else if (btn.classList.contains('ban-btn')) {
            showBanModal(userId, userName);
        } else if (btn.classList.contains('unban-btn')) {
            if (!(await confirmBox(`Unban ${userName}?`, 'Unban user'))) return;
            await busy(btn, async () => {
                await post('/api/unban-user', { userId });
                toast(`${userName} can use Terp Notes again.`);
                reloadSoon();
            });
        } else if (btn.classList.contains('history-btn')) {
            openHistory(userId, userName);
        }
    });

    // ---------- ban ----------

    let banTarget = null;
    function showBanModal(userId, userName) {
        banTarget = { userId, userName };
        $('banDuration').value = '24';
        $('banReason').value = '';
        $('banUserInfo').textContent = `${userName} won't be able to sign in until the ban ends.`;
        openModal('banModal');
    }
    $('banConfirmBtn').addEventListener('click', async (e) => {
        const reason = $('banReason').value.trim();
        if (!reason) {
            $('banReason').focus();
            return toast('Add a reason for the ban.', 'error');
        }
        const duration = $('banDuration').value;
        const permanent = duration === 'permanent';
        await busy(e.currentTarget, async () => {
            await post('/api/ban-user', {
                userId: banTarget.userId,
                banType: permanent ? 'permanent' : 'timed',
                banReason: reason,
                banDuration: permanent ? null : parseInt(duration, 10),
            });
            closeModal($('banModal'));
            toast(`${banTarget.userName} is banned (${$('banDuration').selectedOptions[0].text.toLowerCase()}).`);
            reloadSoon();
        });
    });

    // ---------- account history ----------

    const history = { userId: null, page: 1, limit: 50, action: '', pages: 1 };
    const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const ACTION_BADGE = { BAN: 'tn-badge-error', DELETE: 'tn-badge-error', REPORT: 'tn-badge-warn' };

    function openHistory(userId, userName) {
        Object.assign(history, { userId, page: 1, action: '' });
        $('historyModalTitle').textContent = `History: ${userName}`;
        $('historyActionFilter').value = '';
        $('historyPageSize').value = String(history.limit);
        openModal('historyModal');
        loadHistory();
    }

    async function loadHistory() {
        if (!history.userId) return;
        const box = $('historyContent');
        box.innerHTML = '<p class="adm-empty">Loading…</p>';
        $('historyPagination').hidden = true;
        try {
            const params = new URLSearchParams({ page: history.page, limit: history.limit });
            if (history.action) params.set('action', history.action);
            const res = await fetch(`/api/user-history/${encodeURIComponent(history.userId)}?${params}`, { credentials: 'same-origin' });
            const data = await res.json();
            if (!data.success) throw new Error();
            if (!data.history || !data.history.length) {
                box.innerHTML = '<p class="adm-empty">No history recorded for this account yet.</p>';
                return;
            }
            box.innerHTML = data.history.map((entry) => `
                <div class="adm-history-row">
                    <span class="tn-badge ${ACTION_BADGE[entry.action] || ''}">${esc(String(entry.action || '').replace(/_/g, ' ').toLowerCase())}</span>
                    <div>
                        <p>${esc(entry.details)}</p>
                        <small>${esc(new Date(entry.timestamp).toLocaleString())}${entry.adminId ? ` · by ${esc(entry.adminId)}` : ''}</small>
                    </div>
                    ${entry.metadata && Object.keys(entry.metadata).length ? `<details><summary>Details</summary><pre>${esc(JSON.stringify(entry.metadata, null, 2))}</pre></details>` : ''}
                </div>`).join('');
            const p = data.pagination || { pages: 1 };
            history.pages = p.pages || 1;
            if (history.pages > 1) {
                $('historyPagination').hidden = false;
                $('historyPaginationInfo').textContent = `${(p.page - 1) * p.limit + 1}–${Math.min(p.page * p.limit, p.total)} of ${p.total}`;
                $('historyPrevPage').disabled = p.page <= 1;
                $('historyNextPage').disabled = p.page >= p.pages;
            }
        } catch {
            box.innerHTML = '<p class="adm-empty">Couldn\'t load the history. Try Refresh.</p>';
        }
    }

    $('historyActionFilter').addEventListener('change', (e) => { history.action = e.target.value; history.page = 1; loadHistory(); });
    $('historyPageSize').addEventListener('change', (e) => { history.limit = parseInt(e.target.value, 10); history.page = 1; loadHistory(); });
    $('refreshHistory').addEventListener('click', loadHistory);
    $('historyPrevPage').addEventListener('click', () => { if (history.page > 1) { history.page--; loadHistory(); } });
    $('historyNextPage').addEventListener('click', () => { if (history.page < history.pages) { history.page++; loadHistory(); } });

    // ---------- course staff ----------

    const inviteForm = $('professor-invite-form');
    inviteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const box = $('invite-result');
        await busy(inviteForm.querySelector('button[type="submit"]'), async () => {
            const result = await post('/api/admin/professor-invites', { email: inviteForm.email.value, classCode: inviteForm.classCode.value });
            box.textContent = '';
            const p = document.createElement('p');
            p.textContent = `Invite for ${result.email} to ${result.classCode} ${result.emailed ? 'was emailed. You can also share this link' : '(email isn\'t set up, so share this link)'}. It works once and expires in 14 days:`;
            const code = document.createElement('code');
            code.id = 'invite-link';
            code.textContent = result.link;
            box.append(p, code);
            box.hidden = false;
            inviteForm.reset();
        });
    });

    // Course field: suggest UMD courses, same as the upload form.
    const courseInput = $('inviteCourse');
    if (window.CoursePicker && courseInput) {
        let timer;
        const combo = window.CoursePicker.combobox(courseInput, $('inviteCourseList'), {
            onInput: (q) => {
                clearTimeout(timer);
                if (q.replace(/\s+/g, '').length < 2) return combo.show([]);
                timer = setTimeout(async () => {
                    try {
                        const data = await (await fetch(`/api/course-suggest?q=${encodeURIComponent(q)}`, { credentials: 'same-origin' })).json();
                        if (courseInput.value.trim() === q) combo.show((data.courses || []).map((c) => ({ value: c.id, label: c.id, detail: c.name })));
                    } catch {
                        combo.show([]);
                    }
                }, 150);
            },
            onPick: (item) => { courseInput.value = item.value; },
        });
    }

    document.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-remove-staff]');
        if (!btn) return;
        const { course, userid } = btn.dataset;
        if (!(await confirmBox(`Remove ${userid} from ${course} staff?`, 'Remove course staff'))) return;
        await busy(btn, async () => {
            await post('/api/admin/course-staff/remove', { classCode: course, userid });
            btn.closest('li').remove();
            document.querySelector('[data-staff-empty]').hidden = document.querySelectorAll('.staff-admin-row').length > 0;
            toast('Removed.');
        });
    });

    // ---------- announcements ----------

    const annForm = $('announcementForm');
    annForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const message = $('announcementMessage').value.trim();
        if (!message) return;
        const type = annForm.querySelector('input[name="announcementType"]:checked').value;
        await busy($('createAnnouncementBtn'), async () => {
            await post('/api/create-announcement', { message, type });
            toast('Announcement posted.');
            reloadSoon();
        });
    });

    let editingId = null;
    $('editAnnouncementForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.currentTarget;
        const type = form.querySelector('input[name="editAnnouncementType"]:checked')?.value || 'info';
        await busy(form.querySelector('button[type="submit"]'), async () => {
            await post('/api/edit-announcement', { announcementId: editingId, message: $('editAnnouncementMessage').value.trim(), type });
            closeModal($('editAnnouncementModal'));
            toast('Announcement updated.');
            reloadSoon();
        });
    });

    document.addEventListener('click', async (e) => {
        const edit = e.target.closest('[data-ann-edit]');
        if (edit) {
            editingId = edit.dataset.id;
            $('editAnnouncementMessage').value = edit.dataset.message;
            const radio = document.querySelector(`input[name="editAnnouncementType"][value="${edit.dataset.type}"]`) || document.querySelector('input[name="editAnnouncementType"]');
            radio.checked = true;
            openModal('editAnnouncementModal');
            return;
        }
        const toggle = e.target.closest('[data-ann-toggle]');
        if (toggle) {
            await busy(toggle, async () => {
                await post('/api/toggle-announcement', { announcementId: toggle.dataset.id });
                toast('Announcement updated.');
                reloadSoon();
            });
            return;
        }
        const del = e.target.closest('[data-ann-delete]');
        if (del) {
            if (!(await confirmBox('Delete this announcement?', 'Delete announcement'))) return;
            await busy(del, async () => {
                await post('/api/delete-announcement', { announcementId: del.dataset.id });
                toast('Announcement deleted.');
                reloadSoon();
            });
        }
    });

    // ---------- tools: index older notes for Study Buddy ----------

    $('study-index-btn').addEventListener('click', async () => {
        const btn = $('study-index-btn');
        const status = $('study-index-status');
        btn.disabled = true;
        let total = 0;
        let skipped = 0;
        let failures = 0;
        const reasons = {};
        try {
            // Each request does a few seconds of work; keep asking until nothing is left.
            for (let i = 0; i < 500; i++) {
                let r = null;
                try {
                    const res = await fetch('/api/admin/study-index', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', credentials: 'same-origin' });
                    r = await res.json().catch(() => null);
                    if (res.status === 401) throw new Error('Your session ended. Sign in again and retry.');
                    if (!res.ok || !r) throw Object.assign(new Error((r && r.error) || `The server timed out (${res.status}).`), { retry: true });
                } catch (err) {
                    if (!err.retry || ++failures > 3) throw err;
                    status.textContent = `${err.message} Retrying…`;
                    await new Promise((done) => setTimeout(done, 1500));
                    continue;
                }
                failures = 0;
                total += r.indexed;
                skipped += r.skipped;
                for (const [kind, info] of Object.entries(r.reasons || {})) {
                    reasons[kind] = reasons[kind] || { count: 0, example: info.example };
                    reasons[kind].count += info.count;
                }
                status.textContent = `Indexed ${total} so far, ${r.remaining} left…`;
                if (r.remaining === 0) break;
            }
            const labels = { unsupported: 'not a text, PDF or Word file', empty: 'no text inside (scanned or image-only)', error: 'failed to read' };
            const why = Object.entries(reasons).map(([kind, info]) => `${info.count} ${labels[kind] || kind} (e.g. ${info.example})`).join('; ');
            status.textContent = `Done. Indexed ${total} file(s).` + (skipped ? ` Skipped ${skipped}: ${why || 'see server logs'}.` : '');
        } catch (err) {
            status.textContent = `${err.message} Indexed ${total} before stopping; press the button again to continue.`;
        } finally {
            btn.disabled = false;
        }
    });

    // Signing out in another tab (logout-confirm.ejs) signs this tab out too.
    window.addEventListener('storage', (e) => {
        if (e.key === 'terpnotes_logout' && e.newValue === 'true') window.location.href = '/?loggedout=true&t=' + Date.now();
    });
})();
