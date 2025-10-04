// Admin Dashboard JavaScript
document.addEventListener('DOMContentLoaded', function () {
    initAdminDashboard();
});

function initAdminDashboard() {
    // Search functionality
    const searchInput = document.getElementById('userSearch');
    const roleFilter = document.getElementById('roleFilter');

    if (searchInput) {
        searchInput.addEventListener('input', filterUsers);
    }

    if (roleFilter) {
        roleFilter.addEventListener('change', filterUsers);
    }

    // Role update functionality
    document.querySelectorAll('.update-role-btn').forEach(btn => {
        btn.addEventListener('click', updateUserRole);
    });

    // Delete user functionality
    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', deleteUser);
    });
}

function filterUsers() {
    const searchTerm = document.getElementById('userSearch')?.value.toLowerCase() || '';
    const roleFilter = document.getElementById('roleFilter')?.value || '';
    const userCards = document.querySelectorAll('.user-card');

    userCards.forEach(card => {
        const userName = card.dataset.name || '';
        const userEmail = card.dataset.email || '';
        const userRole = card.dataset.role || '';

        const matchesSearch = userName.includes(searchTerm) || userEmail.includes(searchTerm);
        const matchesRole = !roleFilter || userRole === roleFilter;

        if (matchesSearch && matchesRole) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

async function updateUserRole(event) {
    const userId = event.target.dataset.userId;
    const roleSelect = document.getElementById(`role-${userId}`);

    if (roleSelect.disabled) {
        showNotification('Cannot modify protected system account', 'error');
        return;
    }

    const newRole = roleSelect.value;

    try {
        const response = await fetch('/api/update-user-role', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                userId: userId,
                newRole: newRole
            })
        });

        const result = await response.json();

        if (response.ok) {
            showNotification('User role updated successfully!', 'success');

            // Update the role display
            const userCard = document.querySelector(`[data-user-id="${userId}"]`);
            if (userCard) {
                const roleSpan = userCard.querySelector('.user-role');
                if (roleSpan) {
                    roleSpan.textContent = newRole;
                    roleSpan.className = `user-role role-${newRole}`;
                }
                userCard.dataset.role = newRole;
            }

            // Update statistics
            updateStatistics();

            // Re-apply current filter
            filterUsers();
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error updating user role: ' + error.message, 'error');
    }
}

function deleteUser(event) {
    const userId = event.target.dataset.userId;
    showConfirmModal(
        'Delete User',
        'Are you sure you want to delete this user? This will permanently delete their account and all their files. This action cannot be undone.',
        () => performDeleteUser(userId)
    );
}

function showConfirmModal(title, message, onConfirm) {
    const modal = document.getElementById('confirmModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalMessage = document.getElementById('modalMessage');
    const confirmBtn = document.getElementById('confirmBtn');
    const cancelBtn = document.getElementById('cancelBtn');

    if (!modal || !modalTitle || !modalMessage || !confirmBtn || !cancelBtn) {
        if (confirm(message)) {
            onConfirm();
        }
        return;
    }

    modalTitle.textContent = title;
    modalMessage.textContent = message;
    modal.style.display = 'flex';

    // Remove existing event listeners
    confirmBtn.replaceWith(confirmBtn.cloneNode(true));
    cancelBtn.replaceWith(cancelBtn.cloneNode(true));

    // Add new event listeners
    document.getElementById('confirmBtn').addEventListener('click', () => {
        modal.style.display = 'none';
        onConfirm();
    });

    document.getElementById('cancelBtn').addEventListener('click', () => {
        modal.style.display = 'none';
    });
}

async function performDeleteUser(userId) {
    try {
        const response = await fetch('/api/delete-user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ userId: userId })
        });

        const result = await response.json();

        if (response.ok) {
            showNotification('User deleted successfully!', 'success');

            // Remove the user card from the UI
            const userCard = document.querySelector(`[data-user-id="${userId}"]`);
            if (userCard) {
                userCard.remove();
            }

            // Update statistics
            updateStatistics();

            // Re-apply current filter
            filterUsers();
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error deleting user: ' + error.message, 'error');
    }
}

function updateStatistics() {
    const userCards = document.querySelectorAll('.user-card');
    let adminCount = 0;
    let contributorCount = 0;
    let viewerCount = 0;

    userCards.forEach(card => {
        const role = card.dataset.role;
        if (role === 'admin') adminCount++;
        else if (role === 'contributor') contributorCount++;
        else if (role === 'viewer') viewerCount++;
    });

    // Update the statistics display
    const totalUsersEl = document.getElementById('totalUsers');
    const adminCountEl = document.getElementById('adminCount');
    const contributorCountEl = document.getElementById('contributorCount');
    const viewerCountEl = document.getElementById('viewerCount');

    if (totalUsersEl) totalUsersEl.textContent = userCards.length;
    if (adminCountEl) adminCountEl.textContent = adminCount;
    if (contributorCountEl) contributorCountEl.textContent = contributorCount;
    if (viewerCountEl) viewerCountEl.textContent = viewerCount;
}

