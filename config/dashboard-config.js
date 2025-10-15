// Dashboard Configuration
// This file contains all configurable settings for the dashboard

const dashboardConfig = {
    // Category configuration with icons and display names
    categories: {
        'Exam': {
            icon: '📝',
            displayName: 'Exam',
            description: 'Exams and test materials'
        },
        'Lecture Notes': {
            icon: '📚',
            displayName: 'Lecture Notes',
            description: 'Class lecture notes and slides'
        },
        'Homework': {
            icon: '✏️',
            displayName: 'Homework',
            description: 'Homework assignments and solutions'
        },
        'Study Guide': {
            icon: '📖',
            displayName: 'Study Guide',
            description: 'Study guides and review materials'
        },
        'Cheat Sheet': {
            icon: '🗒️',
            displayName: 'Cheat Sheet',
            description: 'Quick reference sheets'
        },
        'Project': {
            icon: '💻',
            displayName: 'Project',
            description: 'Course projects and assignments'
        },
        'Lab': {
            icon: '🧪',
            displayName: 'Lab',
            description: 'Lab reports and materials'
        },
        'Lab Report': {
            icon: '🔬',
            displayName: 'Lab Report',
            description: 'Lab reports and materials'
        },
        'Textbook': {
            icon: '📕',
            displayName: 'Textbook',
            description: 'Textbook materials and excerpts'
        },
        'Practice Problems': {
            icon: '🔢',
            displayName: 'Practice Problems',
            description: 'Practice problems and solutions'
        },
        'Other': {
            icon: '📎',
            displayName: 'Other',
            description: 'Other course materials'
        }
    },

    // File type icons configuration
    fileTypeIcons: {
        pdf: {
            icon: '/images/icons/pdf-file.png',
            alt: 'PDF',
            width: 100,
            height: 100
        },
        doc: {
            icon: '/images/icons/word-file.png',
            alt: 'Word',
            width: 100,
            height: 100
        },
        docx: {
            icon: '/images/icons/word-file.png',
            alt: 'Word',
            width: 100,
            height: 100
        },
        xls: {
            icon: '/images/icons/excel-file.png',
            alt: 'Excel',
            width: 100,
            height: 100
        },
        xlsx: {
            icon: '/images/icons/excel-file.png',
            alt: 'Excel',
            width: 100,
            height: 100
        },
        ppt: {
            icon: '/images/icons/powerpoint-file.png',
            alt: 'PowerPoint',
            width: 100,
            height: 100
        },
        pptx: {
            icon: '/images/icons/powerpoint-file.png',
            alt: 'PowerPoint',
            width: 100,
            height: 100
        },
        txt: {
            icon: '/images/icons/text-file.png',
            alt: 'Text',
            width: 100,
            height: 100
        },
        zip: {
            icon: '/images/icons/zip-file.png',
            alt: 'Archive',
            width: 100,
            height: 100
        },
        rar: {
            icon: '/images/icons/zip-file.png',
            alt: 'Archive',
            width: 100,
            height: 100
        },
        jpg: {
            icon: '/images/icons/image-file.png',
            alt: 'Image',
            width: 100,
            height: 100
        },
        jpeg: {
            icon: '/images/icons/image-file.png',
            alt: 'Image',
            width: 100,
            height: 100
        },
        png: {
            icon: '/images/icons/image-file.png',
            alt: 'Image',
            width: 100,
            height: 100
        },
        gif: {
            icon: '/images/icons/image-file.png',
            alt: 'Image',
            width: 100,
            height: 100
        },
        mp4: {
            icon: '/images/icons/video-file.png',
            alt: 'Video',
            width: 100,
            height: 100
        },
        mov: {
            icon: '/images/icons/video-file.png',
            alt: 'Video',
            width: 100,
            height: 100
        },
        mp3: {
            icon: '/images/icons/audio-file.png',
            alt: 'Audio',
            width: 100,
            height: 100
        }
    },

    // Default file icon
    defaultFileIcon: {
        icon: '/images/icons/document.png',
        alt: 'Document',
        width: 100,
        height: 100
    },

    // Status badges configuration
    statusBadges: {
        new: {
            enabled: true,
            thresholdDays: 7,
            icon: '/images/icons/new-badge.png',
            alt: 'New',
            width: 16,
            height: 16,
            background: '#D1FAE5',
            color: '#065F46',
            text: 'New'
        },
        scanned: {
            enabled: true,
            icon: '/images/icons/security-shield-check.png',
            alt: 'Security',
            width: 16,
            height: 16,
            background: '#DCFCE7',
            color: '#166534',
            text: 'Scanned'
        },
        pending: {
            enabled: true,
            icon: '/images/icons/clock-warning.png',
            alt: 'Pending',
            width: 16,
            height: 16,
            background: '#FEF3C7',
            color: '#92400E',
            text: 'Pending'
        },
        error: {
            enabled: true,
            icon: '/images/icons/warning-triangle.png',
            alt: 'Error',
            width: 16,
            height: 16,
            background: '#FEE2E2',
            color: '#DC2626',
            text: 'Error'
        },
        category: {
            enabled: true,
            background: '#E0E7FF',
            color: '#4338CA'
        }
    },

    // Semester configuration
    semesters: {
        colors: {
            'Fall': {
                background: 'linear-gradient(135deg, #FFD700 0%, #FFA500 100%)',
                textColor: '#000000'
            },
            'Spring': {
                background: 'linear-gradient(135deg, #DC143C 0%, #A50E2A 100%)',
                textColor: 'white'
            },
            'Summer': {
                background: 'linear-gradient(135deg, #000000 0%, #333333 100%)',
                textColor: 'white'
            },
            'Winter': {
                background: 'linear-gradient(135deg, #4A90E2 0%, #357ABD 100%)',
                textColor: 'white'
            }
        },
        order: {
            'Spring': 1,
            'Summer': 2,
            'Fall': 3,
            'Winter': 4
        },
        defaultColor: {
            background: 'linear-gradient(135deg, #FFD700 0%, #FFA500 100%)',
            textColor: '#000000'
        }
    },

    // Sort options configuration
    sortOptions: {
        newest: {
            value: 'newest',
            label: 'Newest First',
            description: 'Sort by upload date (newest first)'
        },
        oldest: {
            value: 'oldest',
            label: 'Oldest First',
            description: 'Sort by upload date (oldest first)'
        },
        popular: {
            value: 'popular',
            label: 'Most Downloaded',
            description: 'Sort by download count (most popular first)'
        },
        name: {
            value: 'name',
            label: 'Name (A-Z)',
            description: 'Sort alphabetically by filename'
        },
        'size-desc': {
            value: 'size-desc',
            label: 'Size (Largest)',
            description: 'Sort by file size (largest first)'
        },
        'size-asc': {
            value: 'size-asc',
            label: 'Size (Smallest)',
            description: 'Sort by file size (smallest first)'
        }
    },

    // File size formatting configuration
    fileSize: {
        units: ['B', 'KB', 'MB', 'GB'],
        decimalPlaces: 1,
        threshold: 1024
    },

    // View configuration
    views: {
        default: 'grouped',
        available: ['grid', 'grouped', 'list']
    },

    // UI configuration
    ui: {
        fileCardIconSize: 100,
        badgeIconSize: 16,
        maxFilenameLength: 50,
        animations: {
            enabled: true,
            duration: 300
        }
    }
};

module.exports = dashboardConfig;
