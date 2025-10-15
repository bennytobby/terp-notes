// Dashboard JavaScript functionality - VERSION 11.0 - FOLDER CLOSING FIX
let allFilesData = [];
let currentView = 'grouped';
let selectedFiles = new Set();
let openGroups = new Set(); // Track which groups are open

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Wait for files data to be available
    if (window.allFilesData && window.allFilesData.length > 0) {
        allFilesData = window.allFilesData;
        initializeDashboard();
    } else {
        // Check periodically for files data
        const checkForData = setInterval(() => {
            if (window.allFilesData) {
                allFilesData = window.allFilesData;
                clearInterval(checkForData);
                initializeDashboard();
            }
        }, 100);
    }
});

function initializeDashboard() {
    // Initialize view switching
    initializeViewSwitching();

    // Initialize filters
    initializeFilters();

    // Initialize file selection
    initializeFileSelection();

    // Load dashboard configuration
    loadDashboardConfig();

    // Set initial view
    switchView(currentView);
}

function initializeViewSwitching() {
    const viewButtons = document.querySelectorAll('.view-toggle .button');
    viewButtons.forEach(button => {
        button.addEventListener('click', function() {
            const viewType = this.id.replace('ViewBtn', '').toLowerCase();
            switchView(viewType);
        });
    });
}

function switchView(viewType) {

    // Update current view
    currentView = viewType;

    // Update body class for filter visibility
    document.body.className = document.body.className.replace(/view-\w+/g, '');
    document.body.classList.add('view-' + viewType);

    // Update button states
    const viewButtons = document.querySelectorAll('.view-toggle .button');
    viewButtons.forEach(btn => {
        btn.classList.remove('active');
    });
    document.getElementById(viewType + 'ViewBtn').classList.add('active');

    // Show/hide view containers
    const groupedView = document.getElementById('groupedView');
    const gridView = document.getElementById('gridView');
    const listView = document.getElementById('listView');
    const emptyState = document.getElementById('emptyState');

    if (groupedView) groupedView.style.display = 'none';
    if (gridView) gridView.style.display = 'none';
    if (listView) listView.style.display = 'none';
    if (emptyState) emptyState.style.display = 'none';

    // Check if we have files to display
    if (allFilesData && allFilesData.length > 0) {
        // Apply current filters and render the selected view
        applyFilters();

        // Show the selected view after rendering
        const selectedView = document.getElementById(viewType + 'View');
        if (selectedView) {
            selectedView.style.display = 'block';
        }
    } else {
        // Show empty state
        if (emptyState) {
            emptyState.style.display = 'block';
            emptyState.innerHTML = `
                <div class="empty-state-content">
                    <h3>No files uploaded yet</h3>
                    <p>Be the first to share your academic resources!</p>
                    <button class="button primary" onclick="document.getElementById('fileUploadModal').style.display='block'">
                        Upload Files
                    </button>
                </div>
            `;
        }
    }

    // Reset selections when switching views
    selectedFiles.clear();
    updateSelectedCount();
}

function initializeFilters() {
    // Initialize filter dropdowns
    initializeCategoryDropdown();
    initializeProfessorDropdown();
    initializeMajorDropdown();
    initializeClassDropdown();
    initializeYearDropdown();
    initializeSemesterDropdown();
    initializeSortDropdown();

    // Initialize clear all filters
    const clearAllBtn = document.querySelector('.clear-filters-btn');
    if (clearAllBtn) {
        clearAllBtn.addEventListener('click', clearAllFilters);
    }
}

function initializeCategoryDropdown() {
    const dropdown = document.getElementById('categoryDropdown');
    if (!dropdown) return;

    // Clear only the options, preserve search box if it exists
    const searchBox = dropdown.querySelector('.search-box');
    if (searchBox) {
        dropdown.innerHTML = '';
        dropdown.appendChild(searchBox);
    } else {
        // If no search box, just clear everything
        dropdown.innerHTML = '';
    }

    const categories = [...new Set(allFilesData.map(file => file.category).filter(Boolean))];

    categories.forEach(category => {
        const item = document.createElement('div');
        item.className = 'dropdown-item';
        item.innerHTML = `
            <input type="checkbox" value="${category}" onchange="updateMultiSelect('category'); applyFilters(); updateActiveFilters();">
            <label>${category}</label>
        `;
        dropdown.appendChild(item);
    });
}

function initializeProfessorDropdown() {
    const dropdown = document.getElementById('professorDropdown');
    if (!dropdown) return;

    // Clear only the options, preserve search box if it exists
    const searchBox = dropdown.querySelector('.search-box');
    if (searchBox) {
        dropdown.innerHTML = '';
        dropdown.appendChild(searchBox);
    } else {
        // If no search box, just clear everything
        dropdown.innerHTML = '';
    }

    // Get unique professors from files data
    const professors = [...new Set(allFilesData.map(file => file.professor).filter(Boolean))].sort();

    professors.forEach(professor => {
        const item = document.createElement('div');
        item.className = 'dropdown-item';
        item.innerHTML = `
            <input type="checkbox" value="${professor}" onchange="updateMultiSelect('professor'); applyFilters(); updateActiveFilters();">
            <label>${professor}</label>
        `;
        dropdown.appendChild(item);
    });
}

function initializeMajorDropdown() {
    const dropdown = document.getElementById('majorDropdown');
    if (!dropdown) return;

    // Clear only the options, preserve search box if it exists
    const searchBox = dropdown.querySelector('.search-box');
    if (searchBox) {
        dropdown.innerHTML = '';
        dropdown.appendChild(searchBox);
    } else {
        // If no search box, just clear everything
        dropdown.innerHTML = '';
    }

    const majors = [...new Set(allFilesData.map(file => file.major).filter(Boolean))].sort();

    majors.forEach(major => {
        const item = document.createElement('div');
        item.className = 'dropdown-item';
        item.innerHTML = `
            <input type="checkbox" value="${major}" onchange="updateMultiSelect('major'); applyFilters(); updateActiveFilters();">
            <label>${major}</label>
        `;
        dropdown.appendChild(item);
    });
}

function initializeClassDropdown() {
    const dropdown = document.getElementById('classDropdown');
    if (!dropdown) return;

    // Clear only the options, preserve search box if it exists
    const searchBox = dropdown.querySelector('.search-box');
    if (searchBox) {
        dropdown.innerHTML = '';
        dropdown.appendChild(searchBox);
    } else {
        // If no search box, just clear everything
        dropdown.innerHTML = '';
    }

    const classes = [...new Set(allFilesData.map(file => file.classCode).filter(Boolean))].sort();

    classes.forEach(classCode => {
        const item = document.createElement('div');
        item.className = 'dropdown-item';
        item.innerHTML = `
            <input type="checkbox" value="${classCode}" onchange="updateMultiSelect('class'); applyFilters(); updateActiveFilters();">
            <label>${classCode}</label>
        `;
        dropdown.appendChild(item);
    });
}

function initializeYearDropdown() {
    const dropdown = document.getElementById('yearDropdown');
    if (!dropdown) return;

    // Clear only the options, preserve search box if it exists
    const searchBox = dropdown.querySelector('.search-box');
    if (searchBox) {
        dropdown.innerHTML = '';
        dropdown.appendChild(searchBox);
    } else {
        // If no search box, just clear everything
        dropdown.innerHTML = '';
    }

    const years = [...new Set(allFilesData.map(file => file.year).filter(Boolean).map(year => String(year)))].sort((a, b) => b - a);

    years.forEach(year => {
        const item = document.createElement('div');
        item.className = 'dropdown-item';
        item.innerHTML = `
            <input type="checkbox" value="${year}" onchange="updateMultiSelect('year'); applyFilters(); updateActiveFilters();">
            <label>${year}</label>
        `;
        dropdown.appendChild(item);
    });
}

function initializeSemesterDropdown() {
    const dropdown = document.getElementById('semesterDropdown');
    if (!dropdown) return;

    // Clear only the options, preserve search box if it exists
    const searchBox = dropdown.querySelector('.search-box');
    if (searchBox) {
        dropdown.innerHTML = '';
        dropdown.appendChild(searchBox);
    } else {
        // If no search box, just clear everything
        dropdown.innerHTML = '';
    }

    const semesters = [...new Set(allFilesData.map(file => file.semester).filter(Boolean))].sort();

    semesters.forEach(semester => {
        const item = document.createElement('div');
        item.className = 'dropdown-item';
        item.innerHTML = `
            <input type="checkbox" value="${semester}" onchange="updateMultiSelect('semester'); applyFilters(); updateActiveFilters();">
            <label>${semester}</label>
        `;
        dropdown.appendChild(item);
    });
}

function initializeSortDropdown() {
    const sortFieldDropdown = document.getElementById('sortField');
    const sortOrderDropdown = document.getElementById('sortOrder');

    if (!sortFieldDropdown || !sortOrderDropdown) return;

    // Clear existing options first
    sortFieldDropdown.innerHTML = '';
    sortOrderDropdown.innerHTML = '';

    // Sort field options
    const sortFields = [
        { value: 'date', text: 'Upload Date' },
        { value: 'name', text: 'Name' },
        { value: 'size', text: 'Size' },
        { value: 'professor', text: 'Professor' }
    ];

    // Sort order options
    const sortOrders = [
        { value: 'desc', text: 'Descending' },
        { value: 'asc', text: 'Ascending' }
    ];

    sortFields.forEach(field => {
        const optionElement = document.createElement('option');
        optionElement.value = field.value;
        optionElement.textContent = field.text;
        sortFieldDropdown.appendChild(optionElement);
    });

    sortOrders.forEach(order => {
        const optionElement = document.createElement('option');
        optionElement.value = order.value;
        optionElement.textContent = order.text;
        sortOrderDropdown.appendChild(optionElement);
    });

    // Set defaults
    sortFieldDropdown.value = 'date';
    sortOrderDropdown.value = 'desc';
}

function applyFilters() {
    const filteredFiles = getFilteredFiles();

    // Apply sorting
    const sortField = document.getElementById('sortField')?.value || 'date';
    const sortOrder = document.getElementById('sortOrder')?.value || 'desc';
    const sortedFiles = sortFiles(filteredFiles, sortField, sortOrder);

    // Update active filters display
    updateActiveFilters();

    // Render the current view
    switch(currentView) {
        case 'grouped':
            renderGroupedView(sortedFiles);
            break;
        case 'grid':
            renderGridView(sortedFiles);
            break;
        case 'list':
            renderListView(sortedFiles);
            break;
    }
}

function getFilteredFiles() {
    let filtered = [...allFilesData];

    if (filtered.length === 0) {
        return filtered;
    }

    // Apply search filter first
    const searchInput = document.getElementById('searchInput');
    const searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : '';

    if (searchTerm) {
        filtered = filtered.filter(file => {
            const searchableFields = [
                file.filename || '',
                file.professor || '',
                file.classCode || '',
                file.category || '',
                file.major || '',
                file.description || ''
            ];

            return searchableFields.some(field =>
                field.toLowerCase().includes(searchTerm)
            );
        });
    }

    // Apply "My Files Only" filter
    const myFilesOnlyCheckbox = document.getElementById('myFilesOnly');
    if (myFilesOnlyCheckbox && myFilesOnlyCheckbox.checked) {
        const currentUser = window.currentUser;
        if (currentUser && currentUser.userid) {
            filtered = filtered.filter(file => file.uploadedBy === currentUser.userid);
        }
    }

    // Get filter values
    const selectedCategories = getSelectedValues('categoryDropdown');
    const selectedProfessors = getSelectedValues('professorDropdown');
    const selectedMajors = getSelectedValues('majorDropdown');
    const selectedClasses = getSelectedValues('classDropdown');
    const selectedYears = getSelectedValues('yearDropdown');
    const selectedSemesters = getSelectedValues('semesterDropdown');

    // Apply filters
    if (selectedCategories.length > 0) {
        filtered = filtered.filter(file =>
            selectedCategories.some(cat =>
                file.category && file.category.toLowerCase().includes(cat.toLowerCase())
            )
        );
    }

    if (selectedProfessors.length > 0) {
        filtered = filtered.filter(file =>
            selectedProfessors.some(prof =>
                file.professor && file.professor.toLowerCase().includes(prof.toLowerCase())
            )
        );
    }

    if (selectedMajors.length > 0) {
        filtered = filtered.filter(file =>
            selectedMajors.includes(file.major)
        );
    }

    if (selectedClasses.length > 0) {
        filtered = filtered.filter(file =>
            selectedClasses.includes(file.classCode)
        );
    }

    if (selectedYears.length > 0) {
        filtered = filtered.filter(file =>
            selectedYears.includes(file.year.toString())
        );
    }

    if (selectedSemesters.length > 0) {
        filtered = filtered.filter(file =>
            selectedSemesters.includes(file.semester)
        );
    }

    return filtered;
}

function searchFiles() {
    applyFilters();
}

// Make searchFiles globally accessible
window.searchFiles = searchFiles;

function sortFiles(files, sortField, sortOrder) {
    if (!files || files.length === 0) return files;

    const sortedFiles = [...files];
    const isDescending = sortOrder === 'desc';

    switch (sortField) {
        case 'date':
            return sortedFiles.sort((a, b) => {
                const dateA = new Date(a.uploadDate);
                const dateB = new Date(b.uploadDate);
                return isDescending ? dateB - dateA : dateA - dateB;
            });
        case 'name':
            return sortedFiles.sort((a, b) => {
                const nameA = (a.filename || '').localeCompare(b.filename || '');
                return isDescending ? -nameA : nameA;
            });
        case 'size':
            return sortedFiles.sort((a, b) => {
                const sizeA = (a.size || 0);
                const sizeB = (b.size || 0);
                return isDescending ? sizeB - sizeA : sizeA - sizeB;
            });
        case 'professor':
            return sortedFiles.sort((a, b) => {
                const profA = (a.professor || '').localeCompare(b.professor || '');
                return isDescending ? -profA : profA;
            });
        default:
            return sortedFiles.sort((a, b) => new Date(b.uploadDate) - new Date(a.uploadDate));
    }
}

// Make sortFiles globally accessible
window.sortFiles = sortFiles;

function getSelectedValues(dropdownId) {
    const dropdown = document.getElementById(dropdownId);
    if (!dropdown) {
        return [];
    }

    const checkboxes = dropdown.querySelectorAll('input[type="checkbox"]:checked');
    const values = Array.from(checkboxes).map(cb => cb.value);
    return values;
}

function updateActiveFilters() {
    const activeFiltersContainer = document.getElementById('activeFilters');
    if (!activeFiltersContainer) return;

    const tags = [];

    // Add search term if present
    const searchInput = document.getElementById('searchInput');
    if (searchInput && searchInput.value.trim()) {
        tags.push({type: 'search', value: `Search: "${searchInput.value.trim()}"`});
    }

    // Collect all active filter tags
    const selectedCategories = getSelectedValues('categoryDropdown');
    const selectedProfessors = getSelectedValues('professorDropdown');
    const selectedMajors = getSelectedValues('majorDropdown');
    const selectedClasses = getSelectedValues('classDropdown');
    const selectedYears = getSelectedValues('yearDropdown');
    const selectedSemesters = getSelectedValues('semesterDropdown');

    selectedCategories.forEach(cat => tags.push({type: 'category', value: cat}));
    selectedProfessors.forEach(prof => tags.push({type: 'professor', value: prof}));
    selectedMajors.forEach(major => tags.push({type: 'major', value: major}));
    selectedClasses.forEach(cls => tags.push({type: 'class', value: cls}));
    selectedYears.forEach(year => tags.push({type: 'year', value: year}));
    selectedSemesters.forEach(sem => tags.push({type: 'semester', value: sem}));

    // Add "My Files Only" filter if active
    const myFilesOnlyCheckbox = document.getElementById('myFilesOnly');
    if (myFilesOnlyCheckbox && myFilesOnlyCheckbox.checked) {
        tags.push({type: 'myFiles', value: 'My Files Only'});
    }

    // Always show active filters section
    activeFiltersContainer.style.display = 'block';
    activeFiltersContainer.style.position = 'relative';

    if (tags.length === 0) {
    activeFiltersContainer.innerHTML = `
        <div class="filter-content" style="flex: 1 !important; display: flex !important; align-items: center !important; gap: 1rem !important;">
            <span class="filter-label">Active Filters:</span>
            <div class="filter-tags" id="filterTags" style="flex: 1 !important;">
                <span class="no-filters">No active filters</span>
            </div>
        </div>
        <button onclick="clearAllFilters()" class="button danger small" style="margin-left: auto !important; flex-shrink: 0 !important; white-space: nowrap !important;">Clear All</button>
    `;
        return;
    }

    // Display active filters
    const filterTagsHtml = tags.map(tag => `
        <span class="filter-tag">
            ${tag.value}
            <button onclick="removeFilter('${tag.type}', '${tag.value}')">&times;</button>
        </span>
    `).join('');

    activeFiltersContainer.innerHTML = `
        <div class="filter-content" style="flex: 1 !important; display: flex !important; align-items: flex-start !important; gap: 1rem !important; margin-right: 1rem !important;">
            <span class="filter-label" style="flex-shrink: 0 !important;">Active Filters:</span>
            <div class="filter-tags" id="filterTags" style="flex: 1 !important; display: flex !important; flex-wrap: wrap !important; gap: 0.5rem !important;">
                ${filterTagsHtml}
            </div>
        </div>
        <button onclick="clearAllFilters()" class="button danger small" style="margin-left: auto !important; flex-shrink: 0 !important; white-space: nowrap !important; align-self: flex-start !important;">Clear All</button>
    `;
}


function clearAllFilters() {
    // Clear all dropdowns
    const dropdowns = ['category', 'professor', 'major', 'class', 'year', 'semester'];
    dropdowns.forEach(type => {
        const dropdown = document.getElementById(type + 'Dropdown');
        if (dropdown) {
            const checkboxes = dropdown.querySelectorAll('input[type="checkbox"]');
            checkboxes.forEach(cb => cb.checked = false);
            updateMultiSelect(type);
        }
    });

    // Clear "My Files Only" checkbox
    const myFilesOnlyCheckbox = document.getElementById('myFilesOnly');
    if (myFilesOnlyCheckbox) {
        myFilesOnlyCheckbox.checked = false;
    }

    // Clear search input
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.value = '';
    }

    applyFilters();
}

function removeFilter(type, value) {

    if (type === 'search') {
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.value = '';
        }
    } else if (type === 'myFiles') {
        const myFilesOnlyCheckbox = document.getElementById('myFilesOnly');
        if (myFilesOnlyCheckbox) {
            myFilesOnlyCheckbox.checked = false;
        }
    } else {
        const dropdown = document.getElementById(type + 'Dropdown');
        if (dropdown) {
            const checkbox = dropdown.querySelector(`input[value="${value}"]`);
            if (checkbox) {
                checkbox.checked = false;
                updateMultiSelect(type);
            }
        }
    }

    applyFilters();
}

// Make removeFilter globally accessible
window.removeFilter = removeFilter;

function renderGroupedView(files) {
    const container = document.getElementById('groupedView');
    if (!container) {
        return;
    }

    if (files.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No files match the current filters.</p></div>';
        container.style.display = 'block';
        return;
    }

    // Group files hierarchically: Semester+Year -> Major -> Course Code -> Category
    const hierarchicalGroups = {};

    files.forEach(file => {
        const semesterYear = `${file.semester} ${file.year}`;
        const major = file.major || 'Other';
        const courseCode = file.classCode || 'Unknown';
        const category = file.category || 'Other';

        // Initialize semester-year level
        if (!hierarchicalGroups[semesterYear]) {
            hierarchicalGroups[semesterYear] = {
                name: semesterYear,
                semester: file.semester,
                year: parseInt(file.year),
                majors: {}
            };
        }

        // Initialize major level
        if (!hierarchicalGroups[semesterYear].majors[major]) {
            hierarchicalGroups[semesterYear].majors[major] = {
                name: major,
                courses: {}
            };
        }

        // Initialize course level
        if (!hierarchicalGroups[semesterYear].majors[major].courses[courseCode]) {
            hierarchicalGroups[semesterYear].majors[major].courses[courseCode] = {
                name: courseCode,
                categories: {}
            };
        }

        // Initialize category level (youngest child - shows files)
        if (!hierarchicalGroups[semesterYear].majors[major].courses[courseCode].categories[category]) {
            hierarchicalGroups[semesterYear].majors[major].courses[courseCode].categories[category] = {
                name: category,
                files: []
            };
        }

        // Add file to category
        hierarchicalGroups[semesterYear].majors[major].courses[courseCode].categories[category].files.push(file);
    });

    // Sort semesters from most recent to oldest (Fall 2025 -> Spring of oldest year)
    const sortedSemesterGroups = Object.values(hierarchicalGroups).sort((a, b) => {
        // First sort by year (descending)
        if (b.year !== a.year) {
            return b.year - a.year;
        }
        // Then sort by semester (Fall comes before Spring within same year)
        const semesterOrder = { 'Fall': 0, 'Spring': 1, 'Summer': 2 };
        return (semesterOrder[a.semester] || 3) - (semesterOrder[b.semester] || 3);
    });


    // Render hierarchical grouped view
    container.innerHTML = sortedSemesterGroups.map(semesterGroup => {
        const totalFiles = Object.values(semesterGroup.majors).reduce((total, major) =>
            total + Object.values(major.courses).reduce((courseTotal, course) =>
                courseTotal + Object.values(course.categories).reduce((catTotal, category) =>
                    catTotal + category.files.length, 0), 0), 0);

        return `
            <div class="semester-year-group">
                <div class="semester-year-header" onclick="toggleGroup('${semesterGroup.name.replace(/\s+/g, '_')}')">
                    <span><span class="triangle-icon">▼</span> 📅 ${semesterGroup.name}</span>
                    <span>(${totalFiles} files)</span>
                </div>
                <div class="semester-year-content" id="group_${semesterGroup.name.replace(/\s+/g, '_')}">
                    ${Object.values(semesterGroup.majors).map(majorGroup => {
                        const majorFileCount = Object.values(majorGroup.courses).reduce((total, course) =>
                            total + Object.values(course.categories).reduce((catTotal, category) =>
                                catTotal + category.files.length, 0), 0);

                        return `
                            <div class="major-group">
                                <div class="major-header" onclick="toggleGroup('${majorGroup.name}_${semesterGroup.name.replace(/\s+/g, '_')}')">
                                    <span><span class="triangle-icon">▼</span> 📚 ${majorGroup.name}</span>
                                    <span>(${majorFileCount} files)</span>
                                </div>
                                <div class="major-content" id="group_${majorGroup.name}_${semesterGroup.name.replace(/\s+/g, '_')}">
                                    ${Object.values(majorGroup.courses).map(courseGroup => {
                                        const courseFileCount = Object.values(courseGroup.categories).reduce((total, category) =>
                                            total + category.files.length, 0);

                                        return `
                                            <div class="course-group">
                                                <div class="course-header" onclick="toggleGroup('${courseGroup.name}_${majorGroup.name}_${semesterGroup.name.replace(/\s+/g, '_')}')">
                                                    <span><span class="triangle-icon">▼</span> 📖 ${courseGroup.name}</span>
                                                    <span>(${courseFileCount} files)</span>
                                                </div>
                                                <div class="course-content" id="group_${courseGroup.name}_${majorGroup.name}_${semesterGroup.name.replace(/\s+/g, '_')}">
                                                    ${Object.values(courseGroup.categories).map(categoryGroup => `
                                                        <div class="category-group">
                                                            <div class="category-header" onclick="toggleGroup('${categoryGroup.name}_${courseGroup.name}_${majorGroup.name}_${semesterGroup.name.replace(/\s+/g, '_')}')">
                                                                <span><span class="triangle-icon">▼</span> 📁 ${categoryGroup.name}</span>
                                                                <span>(${categoryGroup.files.length} files)</span>
                                                            </div>
                                                            <div class="category-files grid-view" id="group_${categoryGroup.name}_${courseGroup.name}_${majorGroup.name}_${semesterGroup.name.replace(/\s+/g, '_')}">
                                                                ${categoryGroup.files.map(file => createGroupedFileCard(file)).join('')}
                                                            </div>
                                                        </div>
                                                    `).join('')}
                                                </div>
                                            </div>
                                        `;
                                    }).join('')}
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;
    }).join('');

    container.style.display = 'block';
}

function restoreGroupStates() {
    // Only restore states for groups that have been explicitly opened/closed
    const allGroups = document.querySelectorAll('[id^="group_"]');
    allGroups.forEach(group => {
        const groupId = group.id.replace('group_', '');
        // Only close groups that were explicitly closed, leave others open by default
        if (openGroups.has(groupId)) {
            group.style.display = 'block';
            // Update triangle icon to open
            const header = group.previousElementSibling;
            if (header) {
                const triangle = header.querySelector('.triangle-icon');
                if (triangle) {
                    triangle.textContent = '▼';
                }
            }
        }
        // Don't automatically close groups that haven't been touched
    });
}

function renderGridView(files) {
    const container = document.getElementById('gridView');
    if (!container) return;

    container.innerHTML = `
        <div class="files-grid">
            ${files.map(file => createGridViewItem(file)).join('')}
        </div>
    `;

    container.style.display = 'block';
}

function renderListView(files) {
    const container = document.getElementById('listView');
    if (!container) return;

    container.innerHTML = `
        <div class="files-list">
            ${files.map(file => createListViewItem(file)).join('')}
        </div>
    `;

    container.style.display = 'block';
}

function createGroupedFileCard(file) {
    return `
        <div class="file-card file-selectable" onclick="toggleFileSelection('${file.filename}', event)" style="display: flex; flex-direction: column; height: 100%; position: relative;">
            <input type="checkbox" class="file-checkbox" style="display: none;">
            <div class="download-count-badge" title="${file.downloadCount || 0} downloads">${file.downloadCount || 0}</div>
            <div class="file-card-content" style="flex: 1; display: flex; flex-direction: column;">
                <div class="file-icon-section">
                    ${getFileIcon(file.mimetype)}
                    <div class="file-name-section">
                        <h4 class="file-name">${truncateFilename(file.originalName || file.filename, 18)}</h4>
                    </div>
                </div>
                <div class="file-metadata-section" style="flex: 1;">
                    <div class="metadata-row">
                        <span class="metadata-label">Major:</span>
                        <span class="metadata-pill major-pill">${file.major || 'N/A'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Class:</span>
                        <span class="metadata-pill class-pill">${file.classCode || 'N/A'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Professor:</span>
                        <span class="metadata-text">${file.professor || 'N/A'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Term:</span>
                        <span class="metadata-text">${file.semester || 'N/A'} ${file.year || 'N/A'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Uploaded by:</span>
                        <span class="metadata-text">${file.uploadedBy || 'Unknown'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Description:</span>
                        <span class="metadata-text">${file.description || 'No description'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Size:</span>
                        <span class="metadata-text">${formatFileSize(file.size)}</span>
                    </div>
                </div>
                <div class="file-actions-section" style="display: flex !important; justify-content: flex-end !important; gap: 0.5rem !important; margin-left: auto !important; margin-top: auto !important; width: 100% !important;">
                    <button class="action-btn download-btn" onclick="downloadFile('${file.filename}')" style="flex-shrink: 0;">Download</button>
                    <button class="action-btn delete-btn" onclick="deleteFile('${file.filename}')" style="flex-shrink: 0;">Delete</button>
                    <button class="action-btn report-btn" onclick="reportFile('${file.filename}')" style="flex-shrink: 0;">Report</button>
                    ${canEditFile(file) ? `<button class="action-btn edit-btn" onclick="openEditModal('${file.filename}')" style="flex-shrink: 0;">Edit</button>` : ''}
                </div>
                <div class="file-status-tags">
                    ${generateStatusBadges(file)}
                </div>
            </div>
        </div>
    `;
}

function createGridViewItem(file) {
    return `
        <div class="file-card file-selectable" onclick="toggleFileSelection('${file.filename}', event)" style="display: flex; flex-direction: column; height: 100%; position: relative;">
            <input type="checkbox" class="file-checkbox" style="display: none;">
            <div class="download-count-badge" title="${file.downloadCount || 0} downloads">${file.downloadCount || 0}</div>
            <div class="file-card-content" style="flex: 1; display: flex; flex-direction: column;">
                <div class="file-icon-section">
                    ${getFileIcon(file.mimetype)}
                    <div class="file-name-section">
                        <h4 class="file-name">${truncateFilename(file.originalName || file.filename, 18)}</h4>
                    </div>
                </div>
                <div class="file-metadata-section" style="flex: 1;">
                    <div class="metadata-row">
                        <span class="metadata-label">Major:</span>
                        <span class="metadata-pill major-pill">${file.major || 'N/A'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Class:</span>
                        <span class="metadata-pill class-pill">${file.classCode || 'N/A'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Professor:</span>
                        <span class="metadata-text">${file.professor || 'N/A'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Term:</span>
                        <span class="metadata-text">${file.semester || 'N/A'} ${file.year || 'N/A'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Uploaded by:</span>
                        <span class="metadata-text">${file.uploadedBy || 'Unknown'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Description:</span>
                        <span class="metadata-text">${file.description || 'No description'}</span>
                    </div>
                    <div class="metadata-row">
                        <span class="metadata-label">Size:</span>
                        <span class="metadata-text">${formatFileSize(file.size)}</span>
                    </div>
                </div>
                <div class="file-actions-section" style="display: flex !important; justify-content: flex-end !important; gap: 0.5rem !important; margin-left: auto !important; margin-top: auto !important; width: 100% !important;">
                    <button class="action-btn download-btn" onclick="downloadFile('${file.filename}')" style="flex-shrink: 0;">Download</button>
                    <button class="action-btn delete-btn" onclick="deleteFile('${file.filename}')" style="flex-shrink: 0;">Delete</button>
                    <button class="action-btn report-btn" onclick="reportFile('${file.filename}')" style="flex-shrink: 0;">Report</button>
                    ${canEditFile(file) ? `<button class="action-btn edit-btn" onclick="openEditModal('${file.filename}')" style="flex-shrink: 0;">Edit</button>` : ''}
                </div>
                <div class="file-status-tags">
                    ${generateStatusBadges(file)}
                </div>
            </div>
        </div>
    `;
}

function createListViewItem(file) {
    return `
        <div class="file-list-item file-selectable" onclick="toggleFileSelection('${file.filename}', event)" style="display: flex !important; align-items: center !important; justify-content: space-between !important; width: 100% !important; padding: 1rem !important; margin-bottom: 1rem !important; background: white !important; border-radius: 8px !important; box-shadow: 0 2px 4px rgba(0,0,0,0.1) !important;">
            <input type="checkbox" class="file-checkbox" style="display: none;">
            <div class="download-count-badge" title="${file.downloadCount || 0} downloads">${file.downloadCount || 0}</div>
            <div class="file-list-content" style="display: flex !important; align-items: center !important; flex: 1 !important; gap: 1rem !important;">
                <div class="file-left-content" style="display: flex !important; align-items: center !important; flex: 1 !important; gap: 1rem !important;">
                    <div class="file-icon-section">
                        ${getFileIcon(file.mimetype)}
                    </div>
                    <div class="file-info-section" style="flex: 1 !important;">
                        <h4 class="file-name">${truncateFilename(file.originalName || file.filename, 25)}</h4>
                        <div class="file-meta-list">
                            <span class="file-size">${formatFileSize(file.size)}</span>
                            <span class="file-uploader">by ${file.uploadedBy || 'Unknown'}</span>
                            <span class="file-date">${new Date(file.uploadDate).toLocaleDateString()}</span>
                        </div>
                        <div class="file-status-tags" style="margin-top: 0.5rem !important; display: flex !important; gap: 0.5rem !important; flex-wrap: wrap !important;">
                            ${generateStatusBadges(file)}
                        </div>
                    </div>
                </div>
                <div class="file-right-content" style="display: flex !important; align-items: center !important; margin-left: auto !important; flex-shrink: 0 !important;">
                    <div class="file-actions-section" style="display: flex !important; justify-content: flex-end !important; gap: 0.5rem !important;">
                        <button class="action-btn download-btn" onclick="downloadFile('${file.filename}')" style="flex-shrink: 0 !important;">Download</button>
                        <button class="action-btn delete-btn" onclick="deleteFile('${file.filename}')" style="flex-shrink: 0 !important;">Delete</button>
                        <button class="action-btn report-btn" onclick="reportFile('${file.filename}')" style="flex-shrink: 0 !important;">Report</button>
                        ${canEditFile(file) ? `<button class="action-btn edit-btn" onclick="openEditModal('${file.filename}')" style="flex-shrink: 0 !important;">Edit</button>` : ''}
                    </div>
                </div>
            </div>
        </div>
    `;
}

function getFileIcon(filetype) {
    const defaultSize = 80;

    // Safety check for undefined filetype
    if (!filetype) {
        return `<img src="/images/icons/document.png" alt="File" style="width: ${defaultSize}px; height: ${defaultSize}px;" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline'"><span style="display: none; font-size: 24px;">📁</span>`;
    }

    if (filetype.includes('pdf')) {
        return `<img src="/images/icons/pdf-file.png" alt="PDF" style="width: ${defaultSize}px; height: ${defaultSize}px;" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline'"><span style="display: none; font-size: 24px;">📄</span>`;
    } else if (filetype.includes('word') || filetype.includes('doc')) {
        return `<img src="/images/icons/word-file.png" alt="Word" style="width: ${defaultSize}px; height: ${defaultSize}px;" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline'"><span style="display: none; font-size: 24px;">📝</span>`;
    } else if (filetype.includes('excel') || filetype.includes('spreadsheet')) {
        return `<img src="/images/icons/excel-file.png" alt="Excel" style="width: ${defaultSize}px; height: ${defaultSize}px;" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline'"><span style="display: none; font-size: 24px;">📊</span>`;
    } else if (filetype.includes('powerpoint') || filetype.includes('presentation')) {
        return `<img src="/images/icons/powerpoint-file.png" alt="PowerPoint" style="width: ${defaultSize}px; height: ${defaultSize}px;" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline'"><span style="display: none; font-size: 24px;">📊</span>`;
    } else if (filetype.includes('zip') || filetype.includes('archive')) {
        return `<img src="/images/icons/zip-file.png" alt="Archive" style="width: ${defaultSize}px; height: ${defaultSize}px;" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline'"><span style="display: none; font-size: 24px;">🗜️</span>`;
    } else if (filetype.includes('image')) {
        return `<img src="/images/icons/image-file.png" alt="Image" style="width: ${defaultSize}px; height: ${defaultSize}px;" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline'"><span style="display: none; font-size: 24px;">🖼️</span>`;
    } else if (filetype.includes('text') || filetype.includes('txt')) {
        return `<img src="/images/icons/text-file.png" alt="Text" style="width: ${defaultSize}px; height: ${defaultSize}px;" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline'"><span style="display: none; font-size: 24px;">📄</span>`;
    } else {
        return `<img src="/images/icons/document.png" alt="File" style="width: ${defaultSize}px; height: ${defaultSize}px;" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline'"><span style="display: none; font-size: 24px;">📁</span>`;
    }
}

function generateStatusBadges(file) {
    let badges = '';

    // Add "New" badge for recently uploaded files (within last 7 days)
    const uploadDate = new Date(file.uploadDate);
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);

    if (uploadDate > weekAgo) {
        badges += '<span class="status-badge new-badge"><span class="badge-icon">●</span>NEW</span>';
    }

    if (file.virusScanStatus === 'error' || file.virusScanStatus === 'failed') {
        badges += '<span class="status-badge error-badge"><span class="badge-icon">⚠</span>ERROR</span>';
    } else if (file.virusScanStatus === 'pending' || file.virusScanStatus === 'scanning') {
        badges += '<span class="status-badge pending-badge"><span class="badge-icon">⏳</span>PENDING</span>';
    } else if (file.virusScanStatus === 'clean' || file.virusScanStatus === 'scanned') {
        badges += '<span class="status-badge scanned-badge"><span class="badge-icon">●</span>SCANNED</span>';
    }

    // Add category badge
    if (file.category) {
        badges += `<span class="category-badge">${file.category}</span>`;
    }

    return badges;
}

function truncateFilename(filename, maxLength = 20) {
    if (filename.length <= maxLength) return filename;
    const extension = filename.split('.').pop();
    const nameWithoutExt = filename.substring(0, filename.lastIndexOf('.'));
    const truncated = nameWithoutExt.substring(0, maxLength - extension.length - 4) + '...';
    return truncated + '.' + extension;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function canEditFile(file) {
    // Check if current user can edit this file (owner or admin)
    const currentUser = window.currentUser;
    if (!currentUser) return false;

    return currentUser.userid === file.uploadedBy || currentUser.role === 'admin';
}

function initializeFileSelection() {
    // Initialize select all functionality
    const selectAllBtn = document.getElementById('selectAllBtn');
    if (selectAllBtn) {
        selectAllBtn.addEventListener('click', selectAllFiles);
    }

    // Initialize delete selected functionality
    const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
    if (deleteSelectedBtn) {
        deleteSelectedBtn.addEventListener('click', deleteSelectedFiles);
    }
}

function toggleFileSelection(filename, event) {
    // Prevent event propagation on buttons and interactive elements
    if (event.target.tagName === 'BUTTON' || event.target.closest('.file-actions')) {
        return;
    }

    const fileCard = event.currentTarget;
    const checkbox = fileCard.querySelector('.file-checkbox');

    if (checkbox) {
        checkbox.checked = !checkbox.checked;

        if (checkbox.checked) {
            selectedFiles.add(filename);
            fileCard.classList.add('selected');
        } else {
            selectedFiles.delete(filename);
            fileCard.classList.remove('selected');
        }

        updateSelectedCount();
    }
}

function updateSelectedCount() {
    const selectedCount = selectedFiles.size;
    const deleteBtn = document.getElementById('deleteSelectedBtn');
    const selectAllBtn = document.getElementById('selectAllBtn');

    if (deleteBtn) {
        if (selectedCount > 0) {
            deleteBtn.style.display = 'inline-block';
            deleteBtn.textContent = `Delete Selected (${selectedCount})`;
        } else {
            deleteBtn.style.display = 'none';
        }
    }

    if (selectAllBtn) {
        if (selectedCount > 0) {
            selectAllBtn.textContent = 'Deselect All';
        } else {
            selectAllBtn.textContent = 'Select All';
        }
    }
}

function selectAllFiles() {
    const currentViewElement = document.getElementById(currentView + 'View');
    if (!currentViewElement) return;

    const checkboxes = currentViewElement.querySelectorAll('.file-checkbox');
    const isSelecting = selectedFiles.size === 0;

    checkboxes.forEach(checkbox => {
        checkbox.checked = isSelecting;
        const fileCard = checkbox.closest('.file-card, .file-list-item');
        if (fileCard) {
            const filename = fileCard.querySelector('.file-name').textContent.trim();
            if (isSelecting) {
                selectedFiles.add(filename);
                fileCard.classList.add('selected');
            } else {
                selectedFiles.delete(filename);
                fileCard.classList.remove('selected');
            }
        }
    });

    updateSelectedCount();
}

function deleteSelectedFiles() {
    if (selectedFiles.size === 0) return;

    if (confirm(`Are you sure you want to delete ${selectedFiles.size} selected files?`)) {
        selectedFiles.forEach(filename => {
            deleteFile(filename);
        });
        selectedFiles.clear();
        updateSelectedCount();
    }
}

function downloadFile(filename) {
    window.location.href = `/download/${encodeURIComponent(filename)}`;
}

function deleteFile(filename) {
    if (confirm(`Are you sure you want to delete ${filename}?`)) {
        fetch(`/delete/${encodeURIComponent(filename)}`, {
            method: 'GET'
        })
        .then(response => {
            if (response.ok) {
                showNotification('File deleted successfully', 'success');
                // Remove from local data and re-render
                allFilesData = allFilesData.filter(file => file.filename !== filename);
                selectedFiles.delete(filename);
                applyFilters();
                updateSelectedCount();
            } else {
                showNotification('Failed to delete file', 'error');
            }
        })
        .catch(error => {
            showNotification('Failed to delete file', 'error');
        });
    }
}

function reportFile(filename) {
    const reason = prompt('Please enter the reason for reporting this file:');
    if (reason && reason.trim()) {
        // Send report to server
        fetch('/api/report-file', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                filename: filename,
                reason: reason.trim()
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('File reported successfully', 'success');
            } else {
                showNotification('Failed to report file', 'error');
            }
        })
        .catch(error => {
            showNotification('Failed to report file', 'error');
        });
    }
}


function selectAllFiles() {
    const currentViewElement = document.getElementById(currentView + 'View');
    if (!currentViewElement) return;

    const checkboxes = currentViewElement.querySelectorAll('.file-checkbox');
    checkboxes.forEach(checkbox => {
        checkbox.checked = true;
        const filename = checkbox.value;
        selectedFiles.add(filename);
    });

    updateSelectedCount();
}

function deleteSelectedFiles() {
    if (selectedFiles.size === 0) {
        alert('No files selected');
        return;
    }

    if (confirm(`Are you sure you want to delete ${selectedFiles.size} selected files?`)) {
        // Delete files one by one
        selectedFiles.forEach(filename => {
            window.location.href = `/delete/${encodeURIComponent(filename)}`;
        });
    }
}

function openEditModal(filename) {
    const file = allFilesData.find(f => f.filename === filename);
    if (!file) {
        return;
    }

    // Populate modal with file data
    document.getElementById('editFilename').value = file.filename;
    document.getElementById('editClassCode').value = file.classCode || '';
    document.getElementById('editProfessor').value = file.professor || '';
    document.getElementById('editSemester').value = file.semester || '';
    document.getElementById('editYear').value = file.year || '';
    document.getElementById('editCategory').value = file.category || '';
    document.getElementById('editDescription').value = file.description || '';

    // Show modal
    const modal = document.getElementById('editFileModal');
    if (modal) {
        modal.style.display = 'block';
    }
}

function saveFileChanges() {
    const formData = {
        filename: document.getElementById('editFilename').value,
        classCode: document.getElementById('editClassCode').value,
        professor: document.getElementById('editProfessor').value,
        semester: document.getElementById('editSemester').value,
        year: document.getElementById('editYear').value,
        category: document.getElementById('editCategory').value,
        description: document.getElementById('editDescription').value
    };

    fetch('/api/edit-file', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('File details updated successfully', 'success');
            document.getElementById('editFileModal').style.display = 'none';

            // Update local data
            const fileIndex = allFilesData.findIndex(f => f.filename === formData.filename);
            if (fileIndex !== -1) {
                Object.assign(allFilesData[fileIndex], formData);
            }

            // Re-render current view
            applyFilters();
        } else {
            showNotification(`Update failed: ${data.error}`, 'error');
        }
    })
    .catch(error => {
        showNotification('Failed to update file details', 'error');
    });
}

function closeEditModal() {
    document.getElementById('editFileModal').style.display = 'none';
}

function loadDashboardConfig() {
    fetch('/api/dashboard-config')
        .then(response => response.json())
        .then(config => {
            // Store config globally for use by other functions
            window.dashboardConfig = config;
        })
        .catch(error => {
            // Silent fail for dashboard config
        });
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;

    // Style the notification
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 4px;
        color: white;
        font-weight: 500;
        z-index: 10000;
        max-width: 300px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        opacity: 0;
        transform: translateX(100%);
        transition: all 0.3s ease;
    `;

    // Set background color based on type
    switch(type) {
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

    // Add to page
    document.body.appendChild(notification);

    // Animate in
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(0)';
    }, 100);

    // Remove after delay
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 4000);
}

function toggleGroup(groupId) {
    const groupElement = document.getElementById(`group_${groupId}`);

    if (groupElement) {
        const computedStyle = window.getComputedStyle(groupElement);
        const isVisible = computedStyle.display !== 'none';

        if (isVisible) {
            groupElement.style.setProperty('display', 'none', 'important');
            openGroups.delete(groupId); // Mark as closed
        } else {
            groupElement.style.setProperty('display', 'block', 'important');
            openGroups.add(groupId); // Mark as open
        }

        // Toggle triangle icon
        const header = groupElement.previousElementSibling;
        if (header) {
            const triangle = header.querySelector('.triangle-icon');
            if (triangle) {
                triangle.textContent = isVisible ? '▶' : '▼';
            }
        }
    }
}

// Make all essential functions globally accessible
window.toggleGroup = toggleGroup;
window.switchView = switchView;
window.applyFilters = applyFilters;
window.toggleDropdown = toggleDropdown;
window.updateMultiSelect = updateMultiSelect;
window.clearAllFilters = clearAllFilters;
window.downloadFile = downloadFile;
window.deleteFile = deleteFile;
window.openEditModal = openEditModal;
window.saveFileChanges = saveFileChanges;
window.toggleFileSelection = toggleFileSelection;
window.updateSelectedCount = updateSelectedCount;
window.selectAllFiles = selectAllFiles;
window.deleteSelectedFiles = deleteSelectedFiles;
window.reportFile = reportFile;
window.removeFilter = removeFilter;
window.showNotification = showNotification;

function toggleDropdown(type) {
    const dropdown = document.getElementById(type + 'Dropdown');
    const button = document.getElementById(type + 'Btn');

    if (!dropdown || !button) return;

    // Close all other dropdowns
    const allDropdowns = document.querySelectorAll('.multi-select-dropdown');
    const allButtons = document.querySelectorAll('.multi-select-btn');

    allDropdowns.forEach(dd => {
        if (dd !== dropdown) {
            dd.classList.remove('show');
        }
    });

    allButtons.forEach(btn => {
        if (btn !== button) {
            btn.classList.remove('active');
        }
    });

    // Toggle current dropdown
    const isVisible = dropdown.classList.contains('show');
    if (isVisible) {
        dropdown.classList.remove('show');
    } else {
        dropdown.classList.add('show');
    }
    button.classList.toggle('active', !isVisible);
}

function updateMultiSelect(type) {
    const dropdown = document.getElementById(type + 'Dropdown');
    const label = document.getElementById(type + 'Label');

    if (!dropdown || !label) return;

    const selected = dropdown.querySelectorAll('input[type="checkbox"]:checked');

    if (selected.length === 0) {
        const typeLabels = {
            'category': 'All Categories',
            'semester': 'All Semesters',
            'year': 'All Years',
            'major': 'All Majors',
            'class': 'All Classes',
            'professor': 'All Professors'
        };
        label.textContent = typeLabels[type] || `All ${type.charAt(0).toUpperCase() + type.slice(1)}s`;
    } else if (selected.length === 1) {
        label.textContent = selected[0].value;
    } else {
        label.textContent = `${selected.length} selected`;
    }
}

// Close dropdowns when clicking outside
document.addEventListener('click', function(event) {
    if (!event.target.closest('.multi-select-wrapper')) {
        const allDropdowns = document.querySelectorAll('.multi-select-dropdown');
        const allButtons = document.querySelectorAll('.multi-select-btn');

        allDropdowns.forEach(dd => dd.classList.remove('show'));
        allButtons.forEach(btn => btn.classList.remove('active'));
    }
});

// Make clicking anywhere on dropdown option toggle the checkbox
document.addEventListener('click', function(event) {
    if (event.target.closest('.dropdown-item')) {
        const dropdownItem = event.target.closest('.dropdown-item');
        const checkbox = dropdownItem.querySelector('input[type="checkbox"]');
        if (checkbox) {
            checkbox.checked = !checkbox.checked;

            // Trigger change event to update filters
            const changeEvent = new Event('change', { bubbles: true });
            checkbox.dispatchEvent(changeEvent);
        }
    }
});

// Legacy function compatibility - handle old function calls
function clearFiltersForClosedFolder() {
    clearAllFilters();
}

function toggleCategory(categoryElement) {
    toggleDropdown('category');
}

function filterProfessorOptions(searchTerm) {
    // Filter professor dropdown options based on search term
    const dropdown = document.getElementById('professorDropdown');
    if (!dropdown) return;

    const items = dropdown.querySelectorAll('.dropdown-item');
    items.forEach(item => {
        const label = item.querySelector('label');
        if (label) {
            const text = label.textContent.toLowerCase();
            const matches = text.includes(searchTerm.toLowerCase());
            item.style.display = matches ? 'block' : 'none';
        }
    });
}

// Expose functions globally for onclick handlers
window.switchView = switchView;
window.toggleFileSelection = toggleFileSelection;
window.downloadFile = downloadFile;
window.deleteFile = deleteFile;
window.openEditModal = openEditModal;
window.saveFileChanges = saveFileChanges;
window.closeEditModal = closeEditModal;
window.toggleGroup = toggleGroup;
window.removeFilter = removeFilter;
window.clearAllFilters = clearAllFilters;
window.selectAllFiles = selectAllFiles;
window.deleteSelectedFiles = deleteSelectedFiles;
window.toggleDropdown = toggleDropdown;
window.updateMultiSelect = updateMultiSelect;
window.clearFiltersForClosedFolder = clearFiltersForClosedFolder;
window.toggleCategory = toggleCategory;
window.filterProfessorOptions = filterProfessorOptions;

