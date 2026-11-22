(function () {
    async function request(data) {
        const res = await fetch('/api/folders', data && {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        const result = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(res.status === 401 ? 'Sign in again to use your folders.' : result.error || 'Could not load your folders. Try again.');
        return result;
    }

    const page = document.querySelector('.tn-folders');
    if (page) {
        page.addEventListener('submit', async (event) => {
            const { target: form, submitter } = event;
            const action = form.dataset.folderAction;
            if (!action) return;
            event.preventDefault();
            if (submitter?.disabled) return;
            if (action === 'delete' && !window.confirm('Delete this folder and its saved links?')) return;
            const status = form.querySelector('[role="status"]') || document.createElement('p');
            status.setAttribute('role', 'status');
            status.textContent = 'Saving…';
            if (!status.isConnected) form.appendChild(status);
            if (submitter) submitter.disabled = true;
            try {
                const result = await request({ action, ...Object.fromEntries(new FormData(form)) });
                location.href = action === 'delete' ? '/folders' : `/folders?folder=${encodeURIComponent(result.folderId)}`;
            } catch (err) {
                status.textContent = err.message;
                if (submitter) submitter.disabled = false;
            }
        });
    }

    const dialog = document.getElementById('saveFolderDialog');
    if (!dialog) return;

    const form = dialog.querySelector('form');
    const select = document.getElementById('saveFolderSelect');
    const nameField = document.getElementById('saveFolderName');
    const newFolder = document.getElementById('saveFolderNew');
    const button = document.getElementById('saveFolderButton');
    const status = document.getElementById('saveFolderStatus');
    const savedLink = dialog.querySelector('a');
    let active;
    let saving = false;

    function showNewFolder() {
        newFolder.hidden = select.value !== 'new';
        nameField.required = !newFolder.hidden;
    }

    window.NoteFolders = {
        async open(note, opener) {
            if (dialog.open || saving) return;
            const selection = { note, opener };
            active = selection;
            form.reset();
            savedLink.href = '/folders';
            select.replaceChildren();
            select.disabled = true;
            button.disabled = true;
            showNewFolder();
            status.textContent = 'Loading folders…';
            document.getElementById('saveFolderNote').textContent = note.name;
            dialog.showModal();
            try {
                const { folders } = await request();
                if (active !== selection || !dialog.open) return;
                select.replaceChildren(...folders.map(folder => new Option(folder.name, folder.id)), new Option('Create a folder…', 'new'));
                showNewFolder();
                select.disabled = false;
                button.disabled = false;
                status.textContent = '';
            } catch (err) {
                if (active === selection && dialog.open) status.textContent = err.message;
            }
        },
    };

    document.getElementById('closeFolderDialog').addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => active.opener?.focus());
    select.addEventListener('change', () => {
        showNewFolder();
        status.textContent = '';
        button.disabled = false;
    });
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (saving || button.disabled) return;
        saving = true;
        button.disabled = true;
        select.disabled = true;
        nameField.disabled = true;
        status.textContent = 'Saving note…';
        try {
            let folderId = select.value;
            if (folderId === 'new') {
                const name = nameField.value.trim();
                ({ folderId } = await request({ action: 'create', name }));
                select.add(new Option(name, folderId));
                select.value = folderId;
                showNewFolder();
            }
            await request({ action: 'save', folderId, filename: active.note.filename });
            status.textContent = `Saved to ${select.selectedOptions[0].text}.`;
            savedLink.href = `/folders?folder=${encodeURIComponent(folderId)}`;
        } catch (err) {
            status.textContent = err.message;
            button.disabled = false;
        } finally {
            saving = false;
            select.disabled = false;
            nameField.disabled = false;
        }
    });
})();
