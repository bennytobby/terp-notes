/* Terp Notes Server - UMD Resource Sharing Platform */
process.stdin.setEncoding("utf8");

/* MongoDB Connections */
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, './.env') });

// Check for required environment variables
const requiredEnvVars = [
    'MONGO_CONNECTION_STRING',
    'MONGO_DB_NAME',
    'MONGO_FILECOLLECTION',
    'MONGO_USERCOLLECTION',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_REGION',
    'AWS_S3_BUCKET'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
    console.error('Missing required environment variables:', missingVars.join(', '));
    console.error('Please set these variables in your .env file');
}

const uri = process.env.MONGO_CONNECTION_STRING;
const fileCollection = { db: process.env.MONGO_DB_NAME, collection: process.env.MONGO_FILECOLLECTION };
const userCollection = { db: process.env.MONGO_DB_NAME, collection: process.env.MONGO_USERCOLLECTION };
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const client = new MongoClient(uri, { serverApi: ServerApiVersion.v1 });

// Dashboard Configuration
const dashboardConfig = require('./config/dashboard-config');

// Helper function to safely connect to MongoDB
async function ensureConnection() {
    try {
        // Check if client is already connected
        if (client.topology && client.topology.isConnected()) {
            return;
        }

        // If not connected, establish connection
        await client.connect();
    } catch (error) {
        // If connection fails, try to create a new client
        if (error.message.includes('Topology is closed') || error.message.includes('topology')) {
            console.log('MongoDB topology closed, creating new connection...');
            try {
                // Close the old client first
                if (client && typeof client.close === 'function') {
                    await client.close().catch(() => {}); // Ignore close errors
                }

                // Create a completely new client instance
                const newClient = new MongoClient(uri, { serverApi: ServerApiVersion.v1 });
                await newClient.connect();

                // Replace the global client reference
                Object.setPrototypeOf(client, Object.getPrototypeOf(newClient));
                Object.assign(client, newClient);

                console.log('New MongoDB connection established');
            } catch (newConnectionError) {
                console.error('Failed to create new MongoDB connection:', newConnectionError);
                throw newConnectionError;
            }
        } else {
            throw error;
        }
    }
}

/* AWS Connection */
const AWS = require('aws-sdk');
if (process.env.NODE_ENV !== 'production') {
    process.removeAllListeners('warning');
}
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION
});
const AWS_BUCKET = process.env.AWS_S3_BUCKET;

/* VirusTotal Configuration */
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VIRUSTOTAL_ENABLED = !!VIRUSTOTAL_API_KEY;
if (VIRUSTOTAL_ENABLED) {
    console.log('VirusTotal integration enabled');
} else {
    console.log('VirusTotal integration disabled (no API key found)');
}

/* UMD.io API Configuration */
const UMD_API_BASE = 'https://api.umd.io/v1';
const UMD_API_ENABLED = true; // Public API, always available

// Helper: Fetch UMD.io data with caching & fallback
async function fetchUMDData(endpoint, cacheKey, cacheDuration = 24 * 60 * 60 * 1000) {
    try {
        const cacheClient = new MongoClient(uri, { serverApi: ServerApiVersion.v1 });
        await cacheClient.connect();

        // Check cache first
        const cached = await cacheClient
            .db(fileCollection.db)
            .collection('api_cache')
            .findOne({ key: cacheKey });

        const now = new Date();
        if (cached && (now - new Date(cached.timestamp)) < cacheDuration) {
            await cacheClient.close();
            return cached.data;
        }

        // Fetch from API
        const response = await fetch(`${UMD_API_BASE}${endpoint}`);
        if (!response.ok) throw new Error(`API returned ${response.status}`);

        const data = await response.json();

        // Update cache
        await cacheClient
            .db(fileCollection.db)
            .collection('api_cache')
            .updateOne(
                { key: cacheKey },
                { $set: { key: cacheKey, data: data, timestamp: now } },
                { upsert: true }
            );

        await cacheClient.close();
        return data;
    } catch (error) {
        console.error(`UMD.io API error (${endpoint}):`, error.message);

        // Fallback to stale cache if available
        try {
            const fallbackClient = new MongoClient(uri, { serverApi: ServerApiVersion.v1 });
            await fallbackClient.connect();
            const staleCache = await fallbackClient
                .db(fileCollection.db)
                .collection('api_cache')
                .findOne({ key: cacheKey });
            await fallbackClient.close();

            if (staleCache) {
                console.log(`Using stale cache for ${cacheKey}`);
                return staleCache.data;
            }
        } catch (fallbackError) {
            console.error('Fallback cache error:', fallbackError);
        }

        return null;
    }
}

/* Port Configuration */
const portNumber = process.env.PORT || 3000;
console.log(`Terp Notes Server starting on port ${portNumber}`);

/* Express Setup */
const express = require("express");
const { Resend } = require('resend');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
const FormData = require('form-data');
const emailTemplates = require('./emails/templates');
const { validatePassword, getPasswordRequirements } = require('./utils/passwordValidator');
const { sessionTimeout } = require('./middleware/sessionTimeout');
const app = express();

// API endpoint to get dashboard configuration
app.get('/api/dashboard-config', (req, res) => {
    try {
        res.json(dashboardConfig);
    } catch (error) {
        console.error('Error getting dashboard config:', error);
        res.status(500).json({ error: 'Failed to get dashboard configuration' });
    }
});

// Trust proxy - required for Vercel/behind reverse proxy
app.set('trust proxy', 1);

// Security headers
app.use(helmet({
    contentSecurityPolicy: false // Allow inline scripts for EJS
}));

// Rate limiters
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 login attempts
    message: 'Too many login attempts. Please try again in 15 minutes.',
    standardHeaders: true,
    legacyHeaders: false,
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 1000, // Generous limit for testing/mistakes FINDABLE
    message: 'Too many registration attempts. Please try again in an hour.',
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 20, // 20 upload sessions per hour
    message: 'Upload limit reached. Please try again in an hour.',
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 API requests
    message: 'Too many requests. Please slow down.',
});

// Increased body size limits for file uploads
app.use(express.urlencoded({ extended: false, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());
app.set("views", path.resolve(__dirname, "views"));
app.set("view engine", "ejs");

// Serve static files
app.use(express.static(__dirname));
app.use("/styles", express.static(path.join(__dirname, "styles")));
app.use("/js", express.static(path.join(__dirname, "public/js")));
app.use(express.static(path.join(__dirname, "public"))); // Serve logo, favicon, etc.

/* Session Handling - JWT-based */
const session = require("express-session");
const jwt = require('jsonwebtoken');

app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    name: 'terpnotes.sid',
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax',
        path: '/'
    }
}));

/* CRON ENDPOINTS - Must be before session middleware */
// Cron endpoint for Vercel: Scan pending files
app.get('/api/cron/scan-pending-files', async (req, res) => {
    // Verify request is from Vercel Cron (required for security)
    const authHeader = req.get('Authorization');
    if (!process.env.CRON_SECRET) {
        return res.status(500).json({ error: 'CRON_SECRET not configured' });
    }
    if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!VIRUSTOTAL_ENABLED) {
        return res.json({ message: 'VirusTotal disabled' });
    }

    try {
        await ensureConnection();

        // Find files pending scan (uploaded more than 1 minute ago to avoid race conditions)
        const oneMinuteAgo = new Date();
        oneMinuteAgo.setMinutes(oneMinuteAgo.getMinutes() - 1);

        const pendingFiles = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .find({
                virusScanStatus: 'pending',
                uploadDate: { $lt: oneMinuteAgo }
            })
            .limit(5) // Process max 5 files per cron run (avoid timeout)
            .toArray();

        if (pendingFiles.length === 0) {
            return res.json({ message: 'No pending scans', scanned: 0 });
        }

        console.log(`🔄 Cron: Processing ${pendingFiles.length} pending scan(s)...`);

        // Trigger scans (they run asynchronously)
        for (const file of pendingFiles) {
            try {
                const s3Key = file.filename;
                const s3Data = await s3.getObject({ Bucket: AWS_BUCKET, Key: s3Key }).promise();

                // Don't await - let it run in background
                scanFileWithVirusTotal(file._id, s3Data.Body, file.originalName).catch(err => {
                    console.error('Cron scan error:', err);
                });
            } catch (s3Error) {
                console.error('Error fetching file for scan:', s3Error);
            }
        }

        res.json({
            message: `Triggered ${pendingFiles.length} virus scan(s)`,
            scanned: pendingFiles.length
        });

    } catch (error) {
        console.error('Cron endpoint error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Session timeout middleware - MUST come after session initialization
app.use(sessionTimeout);

/* UMD.io Professors API - Must be before session validation middleware */
app.get('/api/umd/professors', async (req, res) => {
    try {
        const { name, course_id, filter_semester, filter_year } = req.query;

        if (course_id) {
            // Fetch professors for a specific course with filtering
            const courseId = course_id.toUpperCase();

            // Determine which semesters to fetch based on filters (same logic as course API)
            let semestersToCheck = [];

            if (filter_semester && filter_year) {
                // Specific semester and year
                const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
                const semesterId = `${filter_year}${semesterMap[filter_semester] || '01'}`;
                semestersToCheck = [semesterId];
            } else if (filter_semester) {
                // All years for this semester
                const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
                const semesterNum = semesterMap[filter_semester] || '01';
                for (let year = 2020; year <= 2025; year++) {
                    semestersToCheck.push(`${year}${semesterNum}`);
                }
            } else if (filter_year) {
                // All semesters for this year
                semestersToCheck = [`${filter_year}01`, `${filter_year}05`, `${filter_year}08`, `${filter_year}12`];
            } else {
                // Default: current semester only
                const now = new Date();
                const currentYear = now.getFullYear();
                const currentMonth = now.getMonth() + 1;

                let currentSemester;
                if (currentMonth >= 1 && currentMonth <= 5) currentSemester = 'Spring';
                else if (currentMonth >= 6 && currentMonth <= 7) currentSemester = 'Summer';
                else if (currentMonth >= 8 && currentMonth <= 12) currentSemester = 'Fall';

                const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
                const currentSemesterId = `${currentYear}${semesterMap[currentSemester] || '01'}`;
                semestersToCheck = [currentSemesterId];
            }

            // Fetch professor data for all required semesters
            const professorData = new Map(); // name -> {name, semesters: [{semester, year, semesterId}]}

            for (const semesterId of semestersToCheck) {
                try {
                    const sectionsData = await fetchUMDData(
                        `/courses/sections?course_id=${courseId}&semester=${semesterId}&per_page=100`,
                        `sections_${courseId}_${semesterId}`,
                        7 * 24 * 60 * 60 * 1000
                    );

                    if (sectionsData && sectionsData.length > 0) {
                        const professors = [...new Set(
                            sectionsData
                                .map(section => section.instructors)
                                .flat()
                                .filter(prof => prof && prof !== 'Instructor: TBA')
                        )];

                        if (professors.length > 0) {
                            // Convert semester ID to readable format
                            const year = semesterId.substring(0, 4);
                            const semesterNum = semesterId.substring(4, 6);
                            const semesterName = {
                                '01': 'Spring', '05': 'Summer', '08': 'Fall', '12': 'Winter'
                            }[semesterNum];

                            // Add professors to our data structure
                            professors.forEach(profName => {
                                if (!professorData.has(profName)) {
                                    professorData.set(profName, {
                                        name: profName,
                                        semesters: []
                                    });
                                }

                                professorData.get(profName).semesters.push({
                                    semester: semesterName,
                                    year: parseInt(year),
                                    semesterId: semesterId
                                });
                            });
                        }
                    }
                } catch (error) {
                    // Silently continue if this semester fails
                }
            }

            // Convert Map to array and sort by name
            const result = Array.from(professorData.values()).sort((a, b) => a.name.localeCompare(b.name));

            return res.json(result);

        } else if (name) {
            // Search professors by name - use the existing UMD.io API
            console.log(`[PROF API] Name search for: ${name}`);
            try {
                const professors = await fetchUMDData(`/professors?name=${name}`, `professors_name_${name}`);

                if (professors && professors.length > 0) {
                    const result = professors.map(p => ({ name: p.name, semesters: [] })).filter(p => p.name && p.name.trim());
                    console.log(`[PROF API] Found ${result.length} professors matching "${name}"`);
                    return res.json(result);
                } else {
                    console.log(`[PROF API] No professors found for "${name}"`);
                    return res.json([]);
                }
            } catch (error) {
                console.log(`[PROF API] Name search failed: ${error.message}`);
                return res.json([]);
            }
        } else {
            // No specific search - return all professors from recent semesters
            console.log(`[PROF API] No specific search - fetching all professors from recent semesters`);

            // Fetch professors from last 2 years (current and previous year)
            const currentYear = new Date().getFullYear();
            const semestersToCheck = [];

            // Add current and previous year semesters
            for (let year = currentYear - 1; year <= currentYear; year++) {
                semestersToCheck.push(`${year}01`, `${year}05`, `${year}08`, `${year}12`);
            }

            console.log(`[PROF API] Fetching professors from ${semestersToCheck.length} recent semesters`);

            // Fetch professor data for recent semesters
            const professorData = new Map(); // name -> {name, semesters: [{semester, year, semesterId}]}

            for (const semesterId of semestersToCheck) {
                try {
                    const sectionsData = await fetchUMDData(
                        `/courses/sections?semester=${semesterId}&per_page=100`,
                        `sections_${semesterId}`,
                        7 * 24 * 60 * 60 * 1000
                    );

                    if (sectionsData && sectionsData.length > 0) {
                        const professors = [...new Set(
                            sectionsData
                                .map(section => section.instructors)
                                .flat()
                                .filter(prof => prof && prof !== 'Instructor: TBA')
                        )];

                        if (professors.length > 0) {
                            // Convert semester ID to readable format
                            const year = semesterId.substring(0, 4);
                            const semesterNum = semesterId.substring(4, 6);
                            const semesterName = {
                                '01': 'Spring', '05': 'Summer', '08': 'Fall', '12': 'Winter'
                            }[semesterNum];

                            // Add professors to our data structure
                            professors.forEach(profName => {
                                if (!professorData.has(profName)) {
                                    professorData.set(profName, {
                                        name: profName,
                                        semesters: []
                                    });
                                }

                                professorData.get(profName).semesters.push({
                                    semester: semesterName,
                                    year: parseInt(year),
                                    semesterId: semesterId
                                });
                            });
                        }
                    }
                } catch (error) {
                    console.log(`[PROF API] Error fetching semester ${semesterId}: ${error.message}`);
                }
            }

            // Convert Map to array and sort by name
            const result = Array.from(professorData.values()).sort((a, b) => a.name.localeCompare(b.name));

            console.log(`[PROF API] Found ${result.length} professors from recent semesters`);
            return res.json(result);
        }
    } catch (error) {
        console.error('[PROF API] Error:', error);
        res.status(500).json({ error: 'Failed to fetch professors' });
    }
});

// API: Get courses taught by a specific professor
app.get('/api/umd/professor-courses', async (req, res) => {
    try {
        const { professor_name, filter_semester, filter_year } = req.query;
        console.log(`[PROF-COURSES API] Request - professor: ${professor_name}, semester: ${filter_semester}, year: ${filter_year}`);

        if (!professor_name || !professor_name.trim()) {
            return res.json([]);
        }

        const professorName = professor_name.trim();

        // Determine which semesters to fetch based on filters (same logic as other APIs)
        let semestersToCheck = [];

        if (filter_semester && filter_year) {
            // Specific semester and year
            const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
            const semesterId = `${filter_year}${semesterMap[filter_semester] || '01'}`;
            semestersToCheck = [semesterId];
            console.log(`[PROF-COURSES API] Fetching specific: ${filter_semester} ${filter_year} (${semesterId})`);
        } else if (filter_semester) {
            // All years for this semester
            const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
            const semesterNum = semesterMap[filter_semester] || '01';
            for (let year = 2020; year <= 2025; year++) {
                semestersToCheck.push(`${year}${semesterNum}`);
            }
            console.log(`[PROF-COURSES API] Fetching all years for ${filter_semester}: ${semestersToCheck.length} semesters`);
        } else if (filter_year) {
            // All semesters for this year
            semestersToCheck = [`${filter_year}01`, `${filter_year}05`, `${filter_year}08`, `${filter_year}12`];
            console.log(`[PROF-COURSES API] Fetching all semesters for ${filter_year}: ${semestersToCheck.length} semesters`);
        } else {
            // Default: current semester only
            const now = new Date();
            const currentYear = now.getFullYear();
            const currentMonth = now.getMonth() + 1;

            let currentSemester;
            if (currentMonth >= 1 && currentMonth <= 5) currentSemester = 'Spring';
            else if (currentMonth >= 6 && currentMonth <= 7) currentSemester = 'Summer';
            else if (currentMonth >= 8 && currentMonth <= 12) currentSemester = 'Fall';

            const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
            const currentSemesterId = `${currentYear}${semesterMap[currentSemester] || '01'}`;
            semestersToCheck = [currentSemesterId];
            console.log(`[PROF-COURSES API] Fetching current semester only: ${currentSemester} ${currentYear} (${currentSemesterId})`);
        }

        // Fetch course data for all required semesters
        const courseData = new Map(); // course_id -> {course_id, name, semesters: [{semester, year, semesterId}]}

        console.log(`[PROF-COURSES API] Fetching course data for ${semestersToCheck.length} semester(s)...`);

        for (const semesterId of semestersToCheck) {
            try {
                console.log(`[PROF-COURSES API] Fetching sections for semester: ${semesterId}`);
                const sectionsData = await fetchUMDData(
                    `/courses/sections?semester=${semesterId}&per_page=100`,
                    `sections_${semesterId}`,
                    7 * 24 * 60 * 60 * 1000
                );

                if (sectionsData && sectionsData.length > 0) {
                    // Filter sections taught by this professor
                    const professorSections = sectionsData.filter(section => {
                        return section.instructors && section.instructors.some(instructor =>
                            instructor && instructor.toLowerCase().includes(professorName.toLowerCase())
                        );
                    });

                    if (professorSections.length > 0) {
                        // Convert semester ID to readable format
                        const year = semesterId.substring(0, 4);
                        const semesterNum = semesterId.substring(4, 6);
                        const semesterName = {
                            '01': 'Spring', '05': 'Summer', '08': 'Fall', '12': 'Winter'
                        }[semesterNum];

                        // Add courses to our data structure
                        professorSections.forEach(section => {
                            const courseId = section.course_id;
                            if (!courseData.has(courseId)) {
                                courseData.set(courseId, {
                                    course_id: courseId,
                                    name: section.course_name || courseId,
                                    semesters: []
                                });
                            }

                            courseData.get(courseId).semesters.push({
                                semester: semesterName,
                                year: parseInt(year),
                                semesterId: semesterId
                            });
                        });

                        console.log(`[PROF-COURSES API] Found ${professorSections.length} sections for ${professorName} in ${semesterName} ${year}`);
                    }
                }
            } catch (error) {
                console.log(`[PROF-COURSES API] Error fetching semester ${semesterId}: ${error.message}`);
            }
        }

        // Convert Map to array and sort by course_id
        const result = Array.from(courseData.values()).sort((a, b) => a.course_id.localeCompare(b.course_id));

        console.log(`[PROF-COURSES API] Found ${result.length} courses for ${professorName}`);
        return res.json(result);

    } catch (error) {
        console.error('[PROF-COURSES API] Error:', error);
        res.status(500).json({ error: 'Failed to fetch professor courses' });
    }
});

// JWT helper functions
function createToken(user) {
    return jwt.sign(user, process.env.SECRET_KEY, { expiresIn: '24h' });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, process.env.SECRET_KEY);
    } catch (err) {
        return null;
    }
}

// Filename sanitization helper function
function sanitizeForHeader(filename) {
    return filename
        .replace(/[^\x20-\x7E]/g, '')
        .replace(/[\r\n\t]/g, ' ')
        .replace(/"/g, "'")
        .trim();
}

// Session validation middleware
app.use(async (req, res, next) => {
    const publicRoutes = ['/', '/login', '/register', '/loginSubmit', '/registerSubmit', '/forgot-password', '/resend-verification', '/privacy', '/terms', '/contact', '/contact/submit', '/api/umd/professors', '/api/umd/courses', '/api/umd/professor-courses'];
    const publicRoutesRegex = /^\/(verify|reset-password)\/.+/; // Match /verify/:token and /reset-password/:token

    const isPublicRoute = publicRoutes.includes(req.path) || publicRoutesRegex.test(req.path);

    // Always restore session from JWT if available (for all routes, public or protected)
    const sessionUser = req.session.user;
    const authToken = req.cookies ? req.cookies.authToken : null;
    const jwtUser = authToken ? verifyToken(authToken) : null;

    if (jwtUser && !sessionUser) {
        req.session.user = jwtUser;
    }

    // Public routes don't require authentication
    if (isPublicRoute) {
        return next();
    }

    // Protected routes require authentication
    if (!req.session.user && req.path !== '/logout') {
        return res.redirect('/login');
    }

    // Check if user is banned (for authenticated users)
    if (req.session.user) {
        try {
            await ensureConnection();
            const user = await client
                .db(userCollection.db)
                .collection(userCollection.collection)
                .findOne({ userid: req.session.user.userid });

            if (user && user.banStatus && user.banStatus.isBanned) {
                // Check if timed ban has expired
                if (user.banStatus.banType === 'timed' && user.banStatus.banExpiry && new Date() > user.banStatus.banExpiry) {
                    // Ban expired, revert to viewer
                    await client
                        .db(userCollection.db)
                        .collection(userCollection.collection)
                        .updateOne(
                            { userid: req.session.user.userid },
                            {
                                $set: {
                                    role: 'viewer',
                                    'banStatus.isBanned': false,
                                    'banStatus.banType': null,
                                    'banStatus.banReason': null,
                                    'banStatus.bannedAt': null,
                                    'banStatus.bannedBy': null,
                                    'banStatus.banExpiry': null
                                },
                                $push: {
                                    'banStatus.banHistory': {
                                        action: 'expired_auto_unban',
                                        timestamp: new Date(),
                                        reason: 'Timed ban expired, automatically reverted to viewer'
                                    }
                                }
                            }
                        );

                    // Update session
                    req.session.user.role = 'viewer';
                } else if (user.banStatus.isBanned) {
                    // User is still banned, destroy session and redirect
                    req.session.destroy();
                    res.clearCookie('authToken');
                    return res.render('error', {
                        title: "Account Banned",
                        message: `Your account has been banned. Reason: ${user.banStatus.banReason || 'Not specified'}. ${user.banStatus.banType === 'timed' && user.banStatus.banExpiry ? `Ban expires: ${new Date(user.banStatus.banExpiry).toLocaleString()}` : 'This is a permanent ban.'}`,
                        link: "/contact",
                        linkText: "Contact Support"
                    });
                }
            }
        } catch (error) {
            console.error('Error checking ban status:', error);
            // Continue if there's an error checking ban status
        }
    }

    next();
});

/* Email Handling - Resend Only */
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const archiver = require('archiver');

// Test email configuration on startup
console.log('Email Configuration:');
console.log('   RESEND_API_KEY:', process.env.RESEND_API_KEY ? 'Set' : 'Missing');
console.log('   NODE_ENV:', process.env.NODE_ENV || 'development');
console.log('   VERCEL_URL:', process.env.VERCEL_URL || 'Not set');

if (resend) {
    console.log('Resend email service initialized');
} else {
    console.error('Resend API key missing - email functionality will not work');
}

/**
 * Send email using Resend
 * @param {string} to - Recipient email address
 * @param {string} subject - Email subject
 * @param {string} html - HTML email content
 * @param {Array} attachments - Optional array of attachments
 * @returns {Promise} Resend response
 */
async function sendEmail(to, subject, html, attachments = []) {
    if (!resend) {
        console.error('Cannot send email: Resend not initialized');
        throw new Error('Email service not configured');
    }

    try {
        console.log(`Sending email via Resend to: ${to}`);
        console.log(`Subject: ${subject}`);
        if (attachments.length > 0) {
            console.log(`Attachments: ${attachments.length} files`);
        }

        const emailData = {
            from: 'Terp Notes <noreply@terp-notes.org>',
            to: to,
            subject: subject,
            html: html
        };

        // Add attachments if provided
        if (attachments.length > 0) {
            emailData.attachments = attachments;
        }

        const result = await resend.emails.send(emailData);

        console.log('Email sent successfully via Resend');
        console.log('Email ID:', result.data?.id);
        return result;

    } catch (error) {
        console.error('Failed to send email via Resend:');
        console.error('Error:', error.message);
        throw error;
    }
}

/**
 * Download file from S3 and return as buffer
 * @param {string} filename - S3 key/filename
 * @returns {Buffer} File content as buffer
 */
async function downloadFileFromS3(filename) {
    try {
        const params = {
            Bucket: AWS_BUCKET,
            Key: filename
        };

        const data = await s3.getObject(params).promise();
        return data.Body;
    } catch (error) {
        console.error(`Failed to download file from S3: ${filename}`, error);
        throw error;
    }
}

/**
 * Create zip file from multiple files
 * @param {Array} files - Array of {name, buffer} objects
 * @returns {Buffer} Zip file as buffer
 */
async function createZipFromFiles(files) {
    return new Promise((resolve, reject) => {
        const archive = archiver('zip', { zlib: { level: 9 } });
        const chunks = [];

        archive.on('data', (chunk) => chunks.push(chunk));
        archive.on('end', () => resolve(Buffer.concat(chunks)));
        archive.on('error', reject);

        files.forEach(file => {
            archive.append(file.buffer, { name: file.name });
        });

        archive.finalize();
    });
}


/* Password Hashing */
const bcrypt = require('bcrypt');

/* File Hashing for Deduplication */
const crypto = require('crypto');

// No default accounts created
// All users register as contributors
console.log('No default accounts - manually set admin via MongoDB');

// Create database indexes for performance
async function createDatabaseIndexes() {
    const indexClient = new MongoClient(uri, { serverApi: ServerApiVersion.v1 });
    try {
        await indexClient.connect();

        // Users collection indexes
        await indexClient
            .db(userCollection.db)
            .collection(userCollection.collection)
            .createIndex({ userid: 1 }, { unique: true });

        await indexClient
            .db(userCollection.db)
            .collection(userCollection.collection)
            .createIndex({ email: 1 }, { unique: true });

        await indexClient
            .db(userCollection.db)
            .collection(userCollection.collection)
            .createIndex({ role: 1 });

        await indexClient
            .db(userCollection.db)
            .collection(userCollection.collection)
            .createIndex({ isVerified: 1, createdAt: 1 }); // For cleanup queries

        // Files collection indexes
        await indexClient
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .createIndex({ classCode: 1 });

        await indexClient
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .createIndex({ major: 1 });

        await indexClient
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .createIndex({ uploadedBy: 1 });

        await indexClient
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .createIndex({ fileHash: 1 }); // For deduplication

        await indexClient
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .createIndex({ uploadDate: -1 }); // For sorting by newest

        await indexClient
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .createIndex({ virusScanStatus: 1 }); // For filtering scanned files

        // Reports collection indexes
        await indexClient
            .db(fileCollection.db)
            .collection('reports')
            .createIndex({ status: 1, reportedAt: -1 }); // For admin dashboard

        await indexClient
            .db(fileCollection.db)
            .collection('reports')
            .createIndex({ filename: 1 }); // For cascading deletes

        // Announcements collection indexes
        await indexClient
            .db(fileCollection.db)
            .collection('announcements')
            .createIndex({ isActive: 1, createdAt: -1 }); // For dashboard queries

        console.log('Database indexes created successfully');
    } catch (error) {
        // Indexes may already exist, that's fine
        if (error.code !== 85 && error.code !== 86) {
            console.error('Error creating indexes:', error.message);
        }
    } finally {
        await indexClient.close();
    }
}

// Cleanup function: Delete unverified accounts older than 7 days
async function cleanupUnverifiedAccounts() {
    const cleanupClient = new MongoClient(uri, { serverApi: ServerApiVersion.v1 });
    try {
        await cleanupClient.connect();

        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

        const result = await cleanupClient
            .db(userCollection.db)
            .collection(userCollection.collection)
            .deleteMany({
                isVerified: false,
                createdAt: { $lt: sevenDaysAgo }
            });

        if (result.deletedCount > 0) {
            console.log(`🧹 Cleaned up ${result.deletedCount} unverified account(s) older than 7 days`);
        }
    } catch (error) {
        console.error('Error cleaning up unverified accounts:', error);
    } finally {
        await cleanupClient.close();
    }
}

// Retry failed/stuck virus scans on startup
async function retryStuckScans() {
    if (!VIRUSTOTAL_ENABLED) {
        return;
    }

    const scanRetryClient = new MongoClient(uri, { serverApi: ServerApiVersion.v1 });
    try {
        await scanRetryClient.connect();

        // Find files stuck in "pending" or "error" status for more than 10 minutes
        const tenMinutesAgo = new Date();
        tenMinutesAgo.setMinutes(tenMinutesAgo.getMinutes() - 10);

        const stuckFiles = await scanRetryClient
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .find({
                virusScanStatus: { $in: ['pending', 'error'] },
                uploadDate: { $lt: tenMinutesAgo },
                $or: [
                    { scanAttempts: { $exists: false } }, // Legacy files without scanAttempts field
                    { scanAttempts: { $lt: 5 } } // Files with less than 5 attempts
                ],
                // Exclude files with permanent error codes
                $nor: [
                    { "virusScanDetails.error": { $regex: /413|400|422|QuotaExceeded|FileTooBig/ } }
                ]
            })
            .toArray();

        if (stuckFiles.length > 0) {
            console.log(`🔄 Retrying ${stuckFiles.length} stuck virus scan(s)...`);

            for (const file of stuckFiles) {
                // Re-download file from S3 and scan
                try {
                    const s3Data = await s3.getObject({
                        Bucket: AWS_BUCKET,
                        Key: file.filename
                    }).promise();

                    scanFileWithVirusTotal(file._id, s3Data.Body, file.originalName).catch(err => {
                        console.error('Retry scan error:', err);
                    });
                } catch (s3Error) {
                    console.error('Error fetching file for retry scan:', s3Error);
                }
            }
        }
    } catch (error) {
        console.error('Error retrying stuck scans:', error);
    } finally {
        await scanRetryClient.close();
    }
}

// Run on server startup (non-blocking for Vercel serverless)
// These run in the background and won't block requests
if (process.env.NODE_ENV !== 'production') {
    // Only run these in development - Vercel Cron handles them in production
    createDatabaseIndexes().catch(err => console.error('Index creation failed:', err));
    cleanupUnverifiedAccounts().catch(err => console.error('Cleanup failed:', err));
    retryStuckScans().catch(err => console.error('Retry scans failed:', err));

    // Run cleanup every 24 hours (dev only)
    setInterval(() => {
        cleanupUnverifiedAccounts().catch(err => console.error('Cleanup failed:', err));
    }, 24 * 60 * 60 * 1000);
}

/* VirusTotal Scanning Function */
async function scanFileWithVirusTotal(fileId, fileBuffer, filename) {
    if (!VIRUSTOTAL_ENABLED) {
        console.log('VirusTotal disabled, skipping scan for:', filename);
        return;
    }

    // Check if file has already failed too many times or has permanent error codes
    try {
        await ensureConnection();
        const fileDoc = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({ _id: fileId });

        if (fileDoc) {
            const scanAttempts = fileDoc.scanAttempts || 0;
            const maxAttempts = 5;

            // Check for permanent error codes in scan details
            const hasPermanentError = fileDoc.virusScanDetails?.error &&
                (fileDoc.virusScanDetails.error.includes('413') || // File too large
                 fileDoc.virusScanDetails.error.includes('400') || // Bad request
                 fileDoc.virusScanDetails.error.includes('422') || // Unprocessable entity
                 fileDoc.virusScanDetails.error.includes('QuotaExceeded') ||
                 fileDoc.virusScanDetails.error.includes('FileTooBig'));

            if (scanAttempts >= maxAttempts || hasPermanentError) {
                console.log(`Skipping scan for ${filename}: ${hasPermanentError ? 'permanent error detected' : 'max attempts reached'} (${scanAttempts}/${maxAttempts})`);

                // Mark as permanently failed
                await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .updateOne(
                        { _id: fileId },
                        {
                            $set: {
                                virusScanStatus: 'permanently_failed',
                                virusScanDate: new Date(),
                                virusScanDetails: {
                                    ...fileDoc.virusScanDetails,
                                    reason: hasPermanentError ? 'permanent_error' : 'max_attempts_reached',
                                    attempts: scanAttempts
                                }
                            }
                        }
                    );
                return;
            }
        }
    } catch (checkError) {
        console.error('Error checking scan attempts:', checkError);
    }

    try {
        console.log(`Starting virus scan for: ${filename}`);

        // Step 1: Upload file to VirusTotal
        const formData = new FormData();
        formData.append('file', fileBuffer, filename);

        const uploadResponse = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': VIRUSTOTAL_API_KEY
            },
            body: formData
        });

        if (!uploadResponse.ok) {
            throw new Error(`VirusTotal upload failed: ${uploadResponse.status}`);
        }

        const uploadData = await uploadResponse.json();
        const analysisId = uploadData.data.id;

        console.log(` File uploaded to VirusTotal. Analysis ID: ${analysisId}`);

        // Step 2: Wait and check scan results (with retries)
        let scanComplete = false;
        let retries = 0;
        const maxRetries = 10;
        const retryDelay = 15000; // 15 seconds

        while (!scanComplete && retries < maxRetries) {
            await new Promise(resolve => setTimeout(resolve, retryDelay));

            const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY
                }
            });

            if (!analysisResponse.ok) {
                throw new Error(`VirusTotal analysis check failed: ${analysisResponse.status}`);
            }

            const analysisData = await analysisResponse.json();
            const status = analysisData.data.attributes.status;

            if (status === 'completed') {
                scanComplete = true;
                const stats = analysisData.data.attributes.stats;
                const malicious = stats.malicious || 0;
                const suspicious = stats.suspicious || 0;
                const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);

                console.log(`Scan complete for ${filename}: ${malicious} malicious, ${suspicious} suspicious out of ${totalEngines} engines`);

                // Update file metadata
                await ensureConnection();

                if (malicious > 0 || suspicious > 2) {
                    // File is infected - mark and delete
                    await client
                        .db(fileCollection.db)
                        .collection(fileCollection.collection)
                        .updateOne(
                            { _id: fileId },
                            {
                                $set: {
                                    virusScanStatus: 'infected',
                                    virusScanDate: new Date(),
                                    virusScanDetails: {
                                        malicious,
                                        suspicious,
                                        totalEngines,
                                        analysisId
                                    }
                                }
                            }
                        );

                    // Get file info to delete from S3
                    const fileDoc = await client
                        .db(fileCollection.db)
                        .collection(fileCollection.collection)
                        .findOne({ _id: fileId });

                    if (fileDoc) {
                        // Delete from S3
                        try {
                            await s3.deleteObject({ Bucket: AWS_BUCKET, Key: fileDoc.filename }).promise();
                            console.log(`Deleted infected file from S3: ${filename}`);
                        } catch (s3Error) {
                            console.error('Error deleting infected file from S3:', s3Error);
                        }

                        // Delete metadata
                        await client
                            .db(fileCollection.db)
                            .collection(fileCollection.collection)
                            .deleteOne({ _id: fileId });

                        console.log(`INFECTED FILE REMOVED: ${filename} (${malicious} detections)`);
                    }
                } else {
                    // File is clean
                    await client
                        .db(fileCollection.db)
                        .collection(fileCollection.collection)
                        .updateOne(
                            { _id: fileId },
                            {
                                $set: {
                                    virusScanStatus: 'clean',
                                    virusScanDate: new Date(),
                                    virusScanDetails: {
                                        malicious,
                                        suspicious,
                                        totalEngines,
                                        analysisId
                                    }
                                }
                            }
                        );

                    console.log(`File marked as clean: ${filename}`);
                }
            } else {
                retries++;
                console.log(` Scan in progress (${retries}/${maxRetries})...`);
            }
        }

        if (!scanComplete) {
            console.log(`Scan timeout for ${filename}, will remain as pending`);

            // Increment scan attempts on timeout
            try {
                await ensureConnection();
                await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .updateOne(
                        { _id: fileId },
                        {
                            $set: {
                                virusScanStatus: 'timeout',
                                virusScanDate: new Date(),
                                virusScanDetails: { error: 'Scan timeout after maximum retries' }
                            },
                            $inc: { scanAttempts: 1 }
                        }
                    );
                console.log(`Incremented scan attempts for timeout: ${filename}`);
            } catch (dbError) {
                console.error('Error updating timeout status:', dbError);
            }
        }

    } catch (error) {
        console.error(`VirusTotal scan error for ${filename}:`, error.message);

        // On error, increment scan attempts and leave file as 'pending' - don't delete
        try {
            await ensureConnection();
            await client
                .db(fileCollection.db)
                .collection(fileCollection.collection)
                .updateOne(
                    { _id: fileId },
                    {
                        $set: {
                            virusScanStatus: 'error',
                            virusScanDate: new Date(),
                            virusScanDetails: { error: error.message }
                        },
                        $inc: { scanAttempts: 1 }
                    }
                );

            console.log(`Incremented scan attempts for ${filename}`);
        } catch (dbError) {
            console.error('Error updating scan status:', dbError);
        }
    }
}

/* Upload */
const multer = require("multer");
const storage = multer.memoryStorage();

// Whitelist of safe academic file types
const ALLOWED_FILE_TYPES = {
    // Documents
    'application/pdf': ['.pdf'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
    'application/msword': ['.doc'],
    'application/vnd.ms-powerpoint': ['.ppt'],
    'application/vnd.ms-excel': ['.xls'],
    'text/plain': ['.txt'],
    'text/markdown': ['.md'],

    // Images
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'image/gif': ['.gif'],
    'image/svg+xml': ['.svg'],
    'image/webp': ['.webp'],

    // Code files (common for CS courses)
    'text/x-python': ['.py'],
    'text/x-java-source': ['.java'],
    'text/x-c': ['.c'],
    'text/x-c++': ['.cpp', '.cc', '.cxx'],
    'text/javascript': ['.js'],
    'text/html': ['.html', '.htm'],
    'text/css': ['.css'],
    'application/json': ['.json'],
    'text/x-python-script': ['.py'],
    'application/x-python-code': ['.py'],

    // Archives (only .zip for now)
    'application/zip': ['.zip'],
    'application/x-zip-compressed': ['.zip']
};

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB limit
    },
    fileFilter: (req, file, cb) => {
        const ext = '.' + file.originalname.split('.').pop().toLowerCase();
        const mimeType = file.mimetype.toLowerCase();

        // Check if file type is in whitelist
        const allowedExtensions = ALLOWED_FILE_TYPES[mimeType];

        if (allowedExtensions && allowedExtensions.includes(ext)) {
            cb(null, true);
        } else {
            // Also check by extension only (some browsers send incorrect MIME types)
            const isExtensionAllowed = Object.values(ALLOWED_FILE_TYPES)
                .flat()
                .includes(ext);

            if (isExtensionAllowed) {
                cb(null, true);
            } else {
                cb(new Error(`File type not allowed: ${ext}. Only documents, images, code files, and .zip archives are supported.`), false);
            }
        }
    }
});

/* ROUTES */

app.get('/', function (req, res) {
    res.render('index', { title: "Terp Notes - Built for Terps, by Terps" });
});

// Icon Test Page (for development/verification)
app.get('/icon-test', function (req, res) {
    res.render('icon-test', { title: "Icon Test - Terp Notes" });
});

// Legal Pages (accessible both logged in and logged out)
app.get('/privacy', function (req, res) {
    res.render('privacy', {
        title: "Privacy Policy - Terp Notes",
        user: req.session.user || null
    });
});

app.get('/terms', function (req, res) {
    res.render('terms', {
        title: "Terms of Service - Terp Notes",
        user: req.session.user || null
    });
});

app.get('/contact', function (req, res) {
    res.render('contact', {
        title: "Contact & Support - Terp Notes",
        user: req.session.user || null
    });
});

// Contact Form Submission
// API: Get UMD courses for autocomplete
app.get('/api/umd/courses', async (req, res) => {
    try {
        const semester = req.query.semester || '202501'; // Default to Spring 2025
        const courses = await fetchUMDData(`/courses/list?semester=${semester}&per_page=100`, `courses_${semester}`);

        if (!courses) {
            // Fallback to existing class codes from DB if API fails
            await client.connect();
            const existingCodes = await client
                .db(fileCollection.db)
                .collection(fileCollection.collection)
                .distinct('classCode');

            return res.json(existingCodes.map(code => ({ course_id: code, name: code })));
        }

        res.json(courses);
    } catch (error) {
        console.error('Error fetching courses:', error);
        res.status(500).json({ error: 'Failed to fetch courses' });
    }
});

// API: Get course details with comprehensive historical data from UMD.io
app.get('/api/umd/course/:courseId', async (req, res) => {
    try {
        const courseId = req.params.courseId.toUpperCase();
        console.log(`[API] Fetching course data for: ${courseId}`);

        // Get query parameters for filtering
        const querySemester = req.query.filter_semester;
        const queryYear = req.query.filter_year;
        console.log(`[API] Filters - Semester: ${querySemester}, Year: ${queryYear}`);

        // Determine which semesters to fetch based on filters
        let semestersToCheck = [];

        if (querySemester && queryYear) {
            // Specific semester and year
            const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
            const semesterId = `${queryYear}${semesterMap[querySemester] || '01'}`;
            semestersToCheck = [semesterId];
            console.log(`[API] Fetching specific: ${querySemester} ${queryYear} (${semesterId})`);
        } else if (querySemester) {
            // All years for this semester
            const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
            const semesterNum = semesterMap[querySemester] || '01';
            for (let year = 2020; year <= 2025; year++) {
                semestersToCheck.push(`${year}${semesterNum}`);
            }
            console.log(`[API] Fetching all years for ${querySemester}: ${semestersToCheck.length} semesters`);
        } else if (queryYear) {
            // All semesters for this year
            semestersToCheck = [`${queryYear}01`, `${queryYear}05`, `${queryYear}08`, `${queryYear}12`];
            console.log(`[API] Fetching all semesters for ${queryYear}: ${semestersToCheck.length} semesters`);
        } else {
            // Default: current semester only (fast and efficient)
            const now = new Date();
            const currentYear = now.getFullYear();
            const currentMonth = now.getMonth() + 1; // 1-12

            // Determine current semester
            let currentSemester;
            if (currentMonth >= 1 && currentMonth <= 5) currentSemester = 'Spring';
            else if (currentMonth >= 6 && currentMonth <= 7) currentSemester = 'Summer';
            else if (currentMonth >= 8 && currentMonth <= 12) currentSemester = 'Fall';

            const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
            const currentSemesterId = `${currentYear}${semesterMap[currentSemester] || '01'}`;

            semestersToCheck = [currentSemesterId];
            console.log(`[API] Fetching current semester only: ${currentSemester} ${currentYear} (${currentSemesterId})`);
        }

        // Fetch course info from first semester to get basic course data
        const firstSemester = semestersToCheck[0];
        const courseData = await fetchUMDData(
            `/courses/${courseId}?semester=${firstSemester}`,
            `course_${courseId}_${firstSemester}`,
            7 * 24 * 60 * 60 * 1000
        );

        if (!courseData || courseData.length === 0) {
            console.log(`[API] Course not found: ${courseId}`);
            return res.status(404).json({ error: 'Course not found' });
        }

        const course = courseData[0];
        console.log(`[API] Course found: ${course.name || courseId}`);

        // Fetch professor data for all required semesters
        const historicalData = {};
        const allProfessors = new Set();
        const allSemesters = new Set();
        const allYears = new Set();

        console.log(`[API] Fetching professor data for ${semestersToCheck.length} semester(s)...`);

        for (const semester of semestersToCheck) {
            try {
                console.log(`[API] Fetching sections for semester: ${semester}`);
                const sectionsData = await fetchUMDData(
                    `/courses/sections?course_id=${courseId}&semester=${semester}&per_page=100`,
                    `sections_${courseId}_${semester}`,
                    7 * 24 * 60 * 60 * 1000
                );

                if (sectionsData && sectionsData.length > 0) {
                    const professors = [...new Set(
                        sectionsData
                            .map(section => section.instructors)
                            .flat()
                            .filter(prof => prof && prof !== 'Instructor: TBA')
                    )];

                    if (professors.length > 0) {
                        // Convert semester ID to readable format
                        const year = semester.substring(0, 4);
                        const semesterNum = semester.substring(4, 6);
                        const semesterName = {
                            '01': 'Spring', '05': 'Summer', '08': 'Fall', '12': 'Winter'
                        }[semesterNum];

                        const key = `${semesterName}_${year}`;
                        historicalData[key] = professors; // Send as array, not Set

                        professors.forEach(prof => allProfessors.add(prof));
                        allSemesters.add(semesterName);
                        allYears.add(year);

                        console.log(`[API] Found ${professors.length} professors for ${semesterName} ${year}: ${professors.join(', ')}`);
                    } else {
                        console.log(`[API] No professors found for ${semester}`);
                    }
                } else {
                    console.log(`[API] No sections found for ${semester}`);
                }
            } catch (error) {
                console.log(`[API] Error fetching data for ${semester}:`, error.message);
            }
        }

        // Convert Sets to Arrays and sort
        const professorList = [...allProfessors].sort();
        const semesterList = [...allSemesters].sort();
        const yearList = [...allYears].sort((a, b) => b - a);

        console.log(` [API] Final results:`);
        console.log(`   - Total professors: ${professorList.length}`);
        console.log(`   - Semesters: ${semesterList.join(', ')}`);
        console.log(`   - Years: ${yearList.join(', ')}`);
        console.log(`   - Historical data keys: ${Object.keys(historicalData).join(', ')}`);

        // Determine current semester for response
        const now = new Date();
        const currentYear = now.getFullYear();
        const currentMonth = now.getMonth() + 1;
        let currentSemester;
        if (currentMonth >= 1 && currentMonth <= 5) currentSemester = 'Spring';
        else if (currentMonth >= 6 && currentMonth <= 7) currentSemester = 'Summer';
        else if (currentMonth >= 8 && currentMonth <= 12) currentSemester = 'Fall';

        res.json({
            course_id: course.course_id || courseId,
            name: course.name || courseId,
            all_professors: professorList,
            filtered_professors: professorList, // Same as all_professors since we filter on server
            historical_semesters: semesterList,
            historical_years: yearList,
            historical_data: historicalData,
            current_semester: currentSemester,
            current_year: currentYear.toString(),
            description: course.description || '',
            source: 'umd_api_historical'
        });
    } catch (error) {
        console.error('[API] Error fetching course details:', error);
        res.status(500).json({ error: 'Failed to fetch course details' });
    }
});

// API: Get all UMD majors
app.get('/api/umd/majors', async (req, res) => {
    try {
        const majors = await fetchUMDData('/majors/list', 'majors_list', 30 * 24 * 60 * 60 * 1000); // Cache 30 days

        if (!majors) {
            // Fallback to existing majors from DB
            await client.connect();
            const existingMajors = await client
                .db(fileCollection.db)
                .collection(fileCollection.collection)
                .distinct('major');

            return res.json(existingMajors.map(m => ({ major_id: m, name: m })));
        }

        res.json(majors);
    } catch (error) {
        console.error('Error fetching majors:', error);
        res.status(500).json({ error: 'Failed to fetch majors' });
    }
});

// Generate presigned URL for direct S3 upload
app.post('/api/get-upload-url', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check if user is viewer
    if (req.session.user.role === 'viewer') {
        return res.status(403).json({ error: 'No upload permission' });
    }

    const { filename, filetype } = req.body;

    if (!filename || !filetype) {
        return res.status(400).json({ error: 'Filename and filetype required' });
    }

    // Generate unique S3 key
    const s3Key = `${Date.now()}_${Math.random().toString(36).substring(7)}_${filename}`;

    // Generate presigned URL (expires in 5 minutes)
    const presignedUrl = s3.getSignedUrl('putObject', {
        Bucket: AWS_BUCKET,
        Key: s3Key,
        ContentType: filetype,
        Expires: 300, // 5 minutes
        ACL: 'private'
    });

    res.json({
        uploadUrl: presignedUrl,
        s3Key: s3Key,
        s3Url: `https://${AWS_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${s3Key}`
    });
});

// Confirm upload and save metadata after direct S3 upload
app.post('/api/confirm-upload', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const {
        s3Key,
        s3Url,
        filename,
        filetype,
        filesize,
        fileHash,
        classCode,
        major,
        professor,
        semester,
        year,
        category,
        description
    } = req.body;


    if (!s3Key || !s3Url || !filename || !classCode || !fileHash) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        await ensureConnection();

        // Check for contextual duplicates (same content AND same context)
        const normalizedClassCode = classCode.trim().toUpperCase();
        const normalizedSemester = semester ? semester.trim() : '';
        const normalizedYear = year ? year.trim() : '';
        const normalizedProfessor = professor ? professor.trim() : '';

        const existingFile = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({
                fileHash: fileHash,
                classCode: normalizedClassCode,
                semester: normalizedSemester,
                year: normalizedYear,
                professor: normalizedProfessor
            });

        if (existingFile) {
            // Delete newly uploaded file from S3 (it's a contextual duplicate)
            await s3.deleteObject({ Bucket: AWS_BUCKET, Key: s3Key }).promise();

            return res.json({
                success: true,
                duplicate: true,
                message: 'File already exists in this context',
                existingFile: existingFile
            });
        }

        // Check if file exists in different context (same content, different metadata)
        const existingFileDifferentContext = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({ fileHash: fileHash });

        if (existingFileDifferentContext) {
            // File exists but in different context - reuse S3 file, create new metadata entry
        }

        // Determine S3 file to use and whether to delete the new upload
        let finalS3Key = s3Key;
        let finalS3Url = s3Url;
        let shouldDeleteNewS3File = false;

        if (existingFileDifferentContext) {
            // Reuse existing S3 file from different context
            finalS3Key = existingFileDifferentContext.filename;
            finalS3Url = existingFileDifferentContext.s3Url;
            shouldDeleteNewS3File = true;
        }

        // Save file metadata
        const fileMeta = {
            filename: finalS3Key,
            originalName: filename,
            s3Url: finalS3Url,
            mimetype: filetype,
            size: filesize,
            fileHash: fileHash,
            uploadDate: new Date(),
            uploadedBy: req.session.user.userid,
            description: description || "",
            classCode: normalizedClassCode,
            major: major || normalizedClassCode.replace(/[0-9]/g, '').trim(),
            semester: normalizedSemester,
            year: normalizedYear,
            professor: normalizedProfessor,
            category: category || "Other",
            virusScanStatus: existingFileDifferentContext ? existingFileDifferentContext.virusScanStatus : 'pending',
            virusScanDate: existingFileDifferentContext ? existingFileDifferentContext.virusScanDate : null,
            virusScanDetails: existingFileDifferentContext ? existingFileDifferentContext.virusScanDetails : null,
            scanAttempts: existingFileDifferentContext ? (existingFileDifferentContext.scanAttempts || 0) : 0
        };

        const insertResult = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .insertOne(fileMeta);

        // Delete the newly uploaded S3 file if we're reusing an existing one
        if (shouldDeleteNewS3File) {
            try {
                await s3.deleteObject({ Bucket: AWS_BUCKET, Key: s3Key }).promise();
            } catch (s3DeleteError) {
                console.error(`Error deleting duplicate S3 file ${s3Key}:`, s3DeleteError);
            }
        }

        // Trigger background virus scan only for new files (not reused ones)
        if (VIRUSTOTAL_ENABLED && !existingFileDifferentContext) {
            s3.getObject({ Bucket: AWS_BUCKET, Key: finalS3Key }).promise()
                .then(s3Data => {
                    scanFileWithVirusTotal(insertResult.insertedId, s3Data.Body, filename).catch(err => {
                        console.error('Background virus scan error:', err);
                    });
                })
                .catch(err => console.error('Error fetching file for scan:', err));
        }

        res.json({
            success: true,
            duplicate: false,
            fileId: insertResult.insertedId,
            message: existingFileDifferentContext ? 'File uploaded successfully (reused from different context)' : 'File uploaded successfully',
            reusedFromDifferentContext: !!existingFileDifferentContext
        });
    } catch (error) {
        console.error('Confirm upload error:', error);
        res.status(500).json({ error: 'Failed to save file metadata' });
    }
});

app.post('/contact/submit', async function (req, res) {
    try {
        const { name, email, subject, message } = req.body;

        if (!name || !email || !subject || !message) {
            return res.render('error', {
                title: "Missing Information",
                message: "Please fill out all required fields.",
                link: "/contact",
                linkText: "Back to Contact"
            });
        }

        // Send email to admin using template
        const adminEmail = process.env.ADMIN_EMAIL || 'paramraj15@gmail.com'; // fallback to your email

        sendEmail(
            adminEmail,
            `[Terp Notes Support] ${subject}`,
            emailTemplates.contactFormEmail(name, email, subject, message)
        ).catch((err) => console.error("Failed to send contact form email:", err.message));

        res.render('success', {
            title: "Message Sent",
            message: "Thank you for contacting us! We'll get back to you within 24-48 hours.",
            link: "/",
            linkText: "Back to Home"
        });
    } catch (error) {
        console.error('Contact form error:', error);
        res.render('error', {
            title: "Submission Error",
            message: "Failed to send message. Please try again later.",
            link: "/contact",
            linkText: "Back to Contact"
        });
    }
});

app.get('/register', function (req, res) {
    res.render('register', { title: "Register - Terp Notes" });
});

app.get('/login', function (req, res) {
    res.render('login', { title: "Login - Terp Notes" });
});

app.get('/forgot-password', function (req, res) {
    res.render('forgot-password', { title: "Forgot Password - Terp Notes" });
});

app.post('/forgot-password', async (req, res) => {
    try {
        await ensureConnection();

        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ email: req.body.email.toLowerCase() });

        if (!user) {
            // Don't reveal if email exists for security
            return res.render('success', {
                title: "Check Your Email",
                message: "If an account exists with that email, a password reset link has been sent.",
                link: "/login",
                linkText: "Back to Login"
            });
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .updateOne(
                { email: req.body.email.toLowerCase() },
                {
                    $set: {
                        resetToken: resetToken,
                        resetTokenExpiry: resetTokenExpiry
                    }
                }
            );

        // Send reset email
        // Fix protocol detection for Vercel (always HTTPS in production)
        const protocol = process.env.NODE_ENV === 'production' ? 'https' : req.protocol;
        const host = process.env.NODE_ENV === 'production' ? process.env.VERCEL_URL : req.get('host');
        const resetLink = `${protocol}://${host}/reset-password/${resetToken}`;

        console.log(`Sending password reset email to ${email}`);
        console.log(`🔗 Reset link: ${resetLink}`);

        // Send email asynchronously using template
        sendEmail(
            req.body.email,
            "Reset Your Terp Notes Password",
            emailTemplates.passwordResetEmail(user.firstname, resetLink)
        ).catch((err) => console.error("Failed to send reset email:", err.message));

        res.render('success', {
            title: "Check Your Email",
            message: "If an account exists with that email, a password reset link has been sent. Please check your inbox and spam folder.",
            link: "/login",
            linkText: "Back to Login"
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.render('error', {
            title: "Error",
            message: "An error occurred. Please try again.",
            link: "/forgot-password",
            linkText: "Try Again"
        });
    }
});

app.get('/reset-password/:token', async (req, res) => {
    const token = req.params.token;

    try {
        await ensureConnection();

        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({
                resetToken: token,
                resetTokenExpiry: { $gt: new Date() }
            });

        if (!user) {
            return res.render('error', {
                title: "Invalid or Expired Link",
                message: "This password reset link is invalid or has expired. Please request a new one.",
                link: "/forgot-password",
                linkText: "Request New Link"
            });
        }

        res.render('reset-password', {
            title: "Reset Password - Terp Notes",
            token: token
        });
    } catch (error) {
        console.error('Reset password page error:', error);
        res.render('error', {
            title: "Error",
            message: "An error occurred. Please try again.",
            link: "/forgot-password",
            linkText: "Back to Forgot Password"
        });
    }
});

app.post('/reset-password/:token', async (req, res) => {
    const token = req.params.token;

    try {
        await ensureConnection();

        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({
                resetToken: token,
                resetTokenExpiry: { $gt: new Date() }
            });

        if (!user) {
            return res.render('error', {
                title: "Invalid or Expired Link",
                message: "This password reset link is invalid or has expired.",
                link: "/forgot-password",
                linkText: "Request New Link"
            });
        }

        if (req.body.password !== req.body.confirm_password) {
            return res.render('error', {
                title: "Password Mismatch",
                message: "The passwords do not match.",
                link: `/reset-password/${token}`,
                linkText: "Try Again"
            });
        }

        // Password strength validation
        const passwordValidation = validatePassword(req.body.password);
        if (!passwordValidation.isValid) {
            return res.render('error', {
                title: "Weak Password",
                message: "Your password does not meet security requirements:\n\n" + passwordValidation.errors.join('\n'),
                link: `/reset-password/${token}`,
                linkText: "Try Again"
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Update password and remove reset token
        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .updateOne(
                { resetToken: token },
                {
                    $set: { pass: hashedPassword },
                    $unset: { resetToken: "", resetTokenExpiry: "" }
                }
            );

        // Send confirmation email using template
        sendEmail(
            user.email,
            "Password Reset Successful - Terp Notes",
            emailTemplates.passwordResetSuccessEmail(user.firstname)
        ).catch((err) => console.error("Failed to send password reset confirmation:", err.message));

        res.render('success', {
            title: "Password Reset Successful",
            message: "Your password has been reset successfully. You can now login with your new password.",
            link: "/login",
            linkText: "Go to Login"
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.render('error', {
            title: "Error",
            message: "Failed to reset password. Please try again.",
            link: "/forgot-password",
            linkText: "Back to Forgot Password"
        });
    }
});

// Email verification route
app.get('/verify/:token', async (req, res) => {
    const token = req.params.token;

    try {
        await ensureConnection();

        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ verificationToken: token });

        if (!user) {
            return res.render('error', {
                title: "Invalid Verification Link",
                message: "This verification link is invalid or has expired. Please register again or request a new verification email.",
                link: "/register",
                linkText: "Back to Registration"
            });
        }

        if (user.isVerified) {
            return res.render('success', {
                title: "Already Verified",
                message: "Your account is already verified. You can login now!",
                link: "/login",
                linkText: "Go to Login"
            });
        }

        // Mark user as verified
        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .updateOne(
                { verificationToken: token },
                {
                    $set: { isVerified: true },
                    $unset: { verificationToken: "" }
                }
            );

        res.render('success', {
            title: "Email Verified! 🎉",
            message: `Welcome to Terp Notes, ${user.firstname}! Your account is now active.`,
            link: "/login",
            linkText: "Login Now"
        });
    } catch (error) {
        console.error('Verification error:', error);
        res.render('error', {
            title: "Verification Failed",
            message: "An error occurred during verification. Please try again.",
            link: "/register",
            linkText: "Back to Registration"
        });
    }
});

// Resend verification email
app.post('/resend-verification', async (req, res) => {
    try {
        await ensureConnection();

        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ email: req.body.email.toLowerCase() });

        if (!user) {
            return res.render('error', {
                title: "Email Not Found",
                message: "No account found with this email address.",
                link: "/login",
                linkText: "Back to Login"
            });
        }

        if (user.isVerified) {
            return res.render('success', {
                title: "Already Verified",
                message: "This account is already verified. You can login!",
                link: "/login",
                linkText: "Go to Login"
            });
        }

        // Generate new verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');

        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .updateOne(
                { email: req.body.email.toLowerCase() },
                { $set: { verificationToken: verificationToken } }
            );

        // Send verification email
        // Fix protocol detection for Vercel (always HTTPS in production)
        const protocol = process.env.NODE_ENV === 'production' ? 'https' : req.protocol;
        const host = process.env.NODE_ENV === 'production' ? process.env.VERCEL_URL : req.get('host');
        const verificationLink = `${protocol}://${host}/verify/${verificationToken}`;

        console.log(`Resending verification email to ${req.body.email}`);
        console.log(`🔗 Verification link: ${verificationLink}`);

        // Send email asynchronously using template
        sendEmail(
            req.body.email,
            "Verify Your Terp Notes Account",
            emailTemplates.resendVerificationEmail(user.firstname, verificationLink)
        ).catch((err) => console.error("Failed to send verification email:", err.message));

        res.render('success', {
            title: "Verification Email Sent",
            message: `A new verification link has been sent to ${req.body.email}. Please check your inbox and spam folder.`,
            link: "/login",
            linkText: "Back to Login"
        });
    } catch (error) {
        console.error('Resend verification error:', error);
        res.render('error', {
            title: "Error",
            message: "Failed to resend verification email. Please try again.",
            link: "/login",
            linkText: "Back to Login"
        });
    }
});

app.get('/dashboard', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        await ensureConnection();

        // Load ALL files once - client-side JavaScript will handle filtering/sorting
        const allFiles = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .find({})
            .sort({ uploadDate: -1 }) // Default sort by newest
            .toArray();

        // Get unique majors and class codes for filter dropdowns
        const uniqueMajors = [...new Set(allFiles.map(f => f.major).filter(Boolean))].sort();
        const uniqueClassCodes = [...new Set(allFiles.map(f => f.classCode).filter(Boolean))].sort();

        // Get unique semesters and years for filter dropdowns
        const uniqueSemesters = [...new Set(allFiles.map(f => f.semester).filter(Boolean))];
        const uniqueYears = [...new Set(allFiles.map(f => f.year).filter(Boolean))].sort((a, b) => b - a); // Descending order (newest first)

        // Sort semesters in academic order: Spring, Summer, Fall, Winter
        const semesterOrder = ['Spring', 'Summer', 'Fall', 'Winter'];
        const sortedSemesters = uniqueSemesters.sort((a, b) =>
            semesterOrder.indexOf(a) - semesterOrder.indexOf(b)
        );

        // Get active announcements
        const announcements = await client
            .db(fileCollection.db)
            .collection('announcements')
            .find({ isActive: true })
            .sort({ createdAt: -1 })
            .toArray();

        res.render('dashboard', {
            firstname: req.session.user.firstname,
            email: req.session.user.email,
            user: req.session.user,
            files: allFiles,
            majors: uniqueMajors,
            classCodes: uniqueClassCodes,
            semesters: sortedSemesters,
            years: uniqueYears,
            announcements: announcements
        });
    } catch (e) {
        console.error(e);
        res.status(500).send("Failed to load dashboard.");
    }
});

app.get('/profile', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        await ensureConnection();
        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ userid: req.session.user.userid });

        res.render('profile', {
            title: "My Profile - Terp Notes",
            user: user
        });
    } catch (error) {
        console.error('Error loading profile:', error);
        res.render('error', {
            title: "Error",
            message: "Failed to load profile.",
            link: "/dashboard",
            linkText: "Back to Dashboard"
        });
    }
});

app.post('/update-profile', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        await ensureConnection();

        // Trim user inputs to prevent spacing issues
        const firstname = req.body.firstname.trim();
        const lastname = req.body.lastname.trim();
        let email = req.body.email.trim().toLowerCase();

        // Check if email is being changed
        if (email !== req.session.user.email) {
            // Validate UMD email domain
            const validDomains = ['umd.edu', 'terpmail.umd.edu'];
            const emailDomain = email.split('@')[1];

            if (!validDomains.includes(emailDomain)) {
                return res.render('error', {
                    title: "Invalid Email Domain",
                    message: "Please use a UMD email address (@umd.edu or @terpmail.umd.edu).",
                    link: "/profile",
                    linkText: "Back to Profile"
                });
            }

            // Normalize email (same logic as registration)
            const emailUsername = email.split('@')[0];
            const normalizedEmail = `${emailUsername}@terpmail.umd.edu`;

            // Check if normalized email already exists (check both formats)
            const existingUser = await client
                .db(userCollection.db)
                .collection(userCollection.collection)
                .findOne({
                    $or: [
                        { email: normalizedEmail },
                        { email: `${emailUsername}@umd.edu` }
                    ]
                });

            if (existingUser && existingUser.userid !== req.session.user.userid) {
                return res.render('error', {
                    title: "Email Already Exists",
                    message: "This email is already registered to another account.",
                    link: "/profile",
                    linkText: "Back to Profile"
                });
            }

            // Use normalized email for update
            email = normalizedEmail;
        }

        // Update user information
        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .updateOne(
                { userid: req.session.user.userid },
                {
                    $set: {
                        firstname: firstname,
                        lastname: lastname,
                        email: email,
                        updatedAt: new Date()
                    }
                }
            );

        // Update session data
        req.session.user.firstname = firstname;
        req.session.user.lastname = lastname;
        req.session.user.email = email;

        // Send confirmation email using template
        sendEmail(
            email,
            "Profile Updated - Terp Notes",
            emailTemplates.profileUpdateEmail(firstname)
        ).catch((err) => console.error("Failed to send profile update confirmation:", err.message));

        res.render('success', {
            title: "Profile Updated",
            message: "Your profile has been successfully updated.",
            link: "/profile",
            linkText: "Back to Profile"
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.render('error', {
            title: "Update Failed",
            message: "Failed to update profile. Please try again.",
            link: "/profile",
            linkText: "Back to Profile"
        });
    }
});

app.post('/change-password', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        await ensureConnection();

        const { currentPassword, newPassword, confirmPassword } = req.body;

        // Verify current password
        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ userid: req.session.user.userid });

        const passwordMatch = await bcrypt.compare(currentPassword, user.pass);
        if (!passwordMatch) {
            return res.render('error', {
                title: "Incorrect Password",
                message: "Your current password is incorrect.",
                link: "/profile",
                linkText: "Back to Profile"
            });
        }

        // Verify new passwords match
        if (newPassword !== confirmPassword) {
            return res.render('error', {
                title: "Password Mismatch",
                message: "New passwords do not match.",
                link: "/profile",
                linkText: "Back to Profile"
            });
        }

        // Password strength validation
        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.isValid) {
            return res.render('error', {
                title: "Weak Password",
                message: "Your new password does not meet security requirements:\n\n" + passwordValidation.errors.join('\n'),
                link: "/profile",
                linkText: "Back to Profile"
            });
        }

        // Verify new password is different from current password
        const samePassword = await bcrypt.compare(newPassword, user.pass);
        if (samePassword) {
            return res.render('error', {
                title: "Same Password",
                message: "Your new password must be different from your current password.",
                link: "/profile",
                linkText: "Back to Profile"
            });
        }

        // Hash and update new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .updateOne(
                { userid: req.session.user.userid },
                {
                    $set: {
                        pass: hashedPassword,
                        updatedAt: new Date()
                    }
                }
            );

        // Send confirmation email using template
        sendEmail(
            user.email,
            "Password Changed - Terp Notes",
            emailTemplates.passwordChangeEmail(user.firstname)
        ).catch((err) => console.error("Failed to send password change confirmation:", err.message));

        res.render('success', {
            title: "Password Changed",
            message: "Your password has been successfully changed.",
            link: "/profile",
            linkText: "Back to Profile"
        });
    } catch (error) {
        console.error('Error changing password:', error);
        res.render('error', {
            title: "Password Change Failed",
            message: "Failed to change password. Please try again.",
            link: "/profile",
            linkText: "Back to Profile"
        });
    }
});

// Delete Account Endpoint
app.delete('/delete-account', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const userId = req.session.user.userid;
    const userEmail = req.session.user.email;

    try {
        await ensureConnection();

        // Check if user is protected (cannot delete protected accounts)
        const userDoc = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ userid: userId });

        if (!userDoc) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (userDoc.isProtected) {
            return res.status(403).json({ error: 'Cannot delete protected system account' });
        }

        console.log(`Deleting account for user: ${userId} (${userEmail})`);

        // Get all files uploaded by this user
        const userFiles = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .find({ uploadedBy: userId })
            .toArray();

        console.log(` Found ${userFiles.length} files to anonymize for user ${userId}`);

        // Anonymize files (keep content, remove personal attribution)
        if (userFiles.length > 0) {
            const updateResult = await client
                .db(fileCollection.db)
                .collection(fileCollection.collection)
                .updateMany(
                    { uploadedBy: userId },
                    {
                        $set: {
                            uploadedBy: 'deleted_user',
                            uploadedByName: 'Deleted User',
                            isDeletedUser: true,
                            originalUploaderId: userId, // Keep reference for admin purposes
                            userDeletedAt: new Date()
                        }
                    }
                );
            console.log(`👤 Anonymized ${updateResult.modifiedCount} files`);
        }

        // Delete user from database
        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .deleteOne({ userid: userId });

        console.log(`Deleted user account: ${userId}`);

        // Send deletion confirmation email using template
        sendEmail(
            userEmail,
            "Account Deleted - Terp Notes",
            emailTemplates.accountDeletionEmail(userDoc.firstname)
        ).catch((err) => console.error("Failed to send account deletion confirmation:", err.message));

        // Clear session and cookies
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destruction error:', err);
            }
        });

        res.clearCookie('authToken');

        console.log(`Account deletion completed for user: ${userId}`);
        res.status(200).json({
            success: true,
            message: 'Account deleted successfully',
            filesDeleted: userFiles.length
        });

    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({
            error: 'Failed to delete account',
            message: 'An error occurred while deleting your account. Please try again or contact support.'
        });
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('authToken');
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).send("Could not log out.");
        }
        res.redirect('/');
    });
});

// Edit file route
app.post('/edit-file', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });

    try {
        const { filename, classCode, professor, semester, year, category, description } = req.body;
        const user = req.session.user;

        // Validate required fields
        if (!filename || !classCode || !professor || !semester || !year || !category || !description) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Connect to MongoDB
        await ensureConnection();

        // Find the file in the database
        const file = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({ filename: filename });

        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Check permissions - only admin or file owner can edit
        if (user.role !== 'admin' && file.uploadedBy !== user.userid) {
            return res.status(403).json({ error: 'You can only edit your own files' });
        }

        // Update file metadata
        const major = classCode.replace(/[0-9]/g, '').trim();

        await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .updateOne(
                { filename: filename },
                {
                    $set: {
                        classCode: classCode,
                        major: major,
                        professor: professor,
                        semester: semester,
                        year: year,
                        category: category,
                        description: description,
                        lastModified: new Date()
                    }
                }
            );

        res.json({ success: true, message: 'File updated successfully' });

    } catch (error) {
        console.error('Edit file error:', error);
        res.status(500).json({ error: 'Failed to update file' });
    }
});

app.get("/delete/:filename", async (req, res) => {
    if (!req.session.user) return res.redirect("/login");

    const filename = decodeURIComponent(req.params.filename);

    try {
        await ensureConnection();

        // Check if user owns the file or is admin
        const fileDoc = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({ filename });

        if (!fileDoc) {
            return res.status(404).send("File not found.");
        }

        if (fileDoc.uploadedBy !== req.session.user.userid && req.session.user.role !== 'admin') {
            console.log('Permission denied - user cannot delete this file');
            return res.status(403).send("You don't have permission to delete this file.");
        }

        // Check if this file is deduplicated (used by other uploads)
        const fileHash = fileDoc.fileHash;
        const duplicateFiles = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .countDocuments({ fileHash: fileHash });

        // Delete metadata from MongoDB FIRST
        await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .deleteOne({ filename });

        // Delete all reports for this specific file
        const deletedReports = await client
            .db(fileCollection.db)
            .collection('reports')
            .deleteMany({ filename: filename });

        if (deletedReports.deletedCount > 0) {
            console.log(` Dismissed ${deletedReports.deletedCount} report(s) for deleted file`);
        }

        // NOW do S3 deletion (after MongoDB is done)
        if (duplicateFiles === 1) {
            await s3.deleteObject({ Bucket: AWS_BUCKET, Key: filename }).promise();
            console.log(`Deleted file from S3: ${filename}`);
        } else {
            console.log(`File is deduplicated (${duplicateFiles} instances), keeping S3 file`);
        }

        // Send email notification to user using template (async, no await needed)
        const originalFilename = filename.split('_').slice(2).join('_'); // Extract original filename from S3 key
        sendEmail(
            req.session.user.email,
            "File Deleted - Terp Notes",
            emailTemplates.fileDeletionEmail(req.session.user.firstname, originalFilename)
        ).catch((err) => console.error("Failed to send file deletion confirmation:", err.message));

        // Send admin notification email with file attachment (async, no await needed)
        const adminEmail = process.env.ADMIN_EMAIL || 'paramraj15@gmail.com';
        const deleterInfo = {
            firstname: req.session.user.firstname,
            lastname: req.session.user.lastname,
            email: req.session.user.email,
            userid: req.session.user.userid,
            role: req.session.user.role
        };

        const fileInfo = {
            filename: filename,
            originalName: originalFilename,
            classCode: fileDoc.classCode,
            semester: fileDoc.semester,
            year: fileDoc.year,
            professor: fileDoc.professor,
            major: fileDoc.major,
            category: fileDoc.category,
            uploadDate: fileDoc.uploadDate,
            downloadCount: fileDoc.downloadCount,
            size: fileDoc.size
        };

        // Download file and send as attachment
        (async () => {
            try {
                const fileBuffer = await downloadFileFromS3(filename);
                const attachment = {
                    filename: originalFilename,
                    content: fileBuffer.toString('base64'),
                    contentType: 'application/octet-stream'
                };

                await sendEmail(
                    adminEmail,
                    `[Terp Notes Admin] File Deleted: ${originalFilename}`,
                    emailTemplates.adminFileDeletionEmail(deleterInfo, fileInfo, 'single'),
                    [attachment]
                );
                console.log('Admin notification sent with file attachment');
            } catch (err) {
                console.error("Failed to send admin file deletion notification with attachment:", err.message);
                // Fallback: send without attachment
                try {
                    await sendEmail(
                        adminEmail,
                        `[Terp Notes Admin] File Deleted: ${originalFilename}`,
                        emailTemplates.adminFileDeletionEmail(deleterInfo, fileInfo, 'single')
                    );
                    console.log('Admin notification sent without attachment (fallback)');
                } catch (fallbackErr) {
                    console.error("Failed to send admin notification even without attachment:", fallbackErr.message);
                }
            }
        })();

        // Redirect back to dashboard
        res.redirect("/dashboard");
    } catch (err) {
        console.error("Delete failed:", err);
        res.status(500).send("Error deleting file.");
    }
});

// Bulk delete endpoint for multiple files
app.post("/api/bulk-delete", apiLimiter, async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { filenames } = req.body;

    if (!filenames || !Array.isArray(filenames) || filenames.length === 0) {
        return res.status(400).json({ error: 'No filenames provided' });
    }

    if (filenames.length > 50) {
        return res.status(400).json({ error: 'Too many files. Maximum 50 files per bulk delete.' });
    }

    const results = {
        success: [],
        failed: [],
        skipped: []
    };

    try {
        await ensureConnection();

        // Get all files that user can delete
        const filesToDelete = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .find({
                filename: { $in: filenames },
                $or: [
                    { uploadedBy: req.session.user.userid },
                    { /* admin can delete any file */ }
                ]
            })
            .toArray();

        // Filter files user can actually delete
        const deletableFiles = filesToDelete.filter(file =>
            file.uploadedBy === req.session.user.userid || req.session.user.role === 'admin'
        );

        if (deletableFiles.length === 0) {
            return res.status(403).json({ error: 'No files found that you can delete' });
        }

        // Store detailed file information for admin notification before deletion
        const deletedFilesDetails = [];

        // Process each file
        for (const file of deletableFiles) {
            try {
                // Store file details before deletion for admin notification
                deletedFilesDetails.push({
                    filename: file.filename,
                    originalName: file.originalName,
                    classCode: file.classCode,
                    semester: file.semester,
                    year: file.year,
                    professor: file.professor,
                    major: file.major,
                    category: file.category,
                    uploadDate: file.uploadDate,
                    downloadCount: file.downloadCount,
                    size: file.size
                });

                // Check if file is deduplicated
                const fileHash = file.fileHash;
                const duplicateFiles = await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .countDocuments({ fileHash: fileHash });

                // Delete metadata from MongoDB
                await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .deleteOne({ filename: file.filename });

                // Delete all reports for this file
                await client
                    .db(fileCollection.db)
                    .collection('reports')
                    .deleteMany({ filename: file.filename });

                // Delete from S3 if not deduplicated
                if (duplicateFiles === 1) {
                    await s3.deleteObject({ Bucket: AWS_BUCKET, Key: file.filename }).promise();
                    console.log(`Deleted file from S3: ${file.filename}`);
                } else {
                    console.log(`File is deduplicated (${duplicateFiles} instances), keeping S3 file: ${file.filename}`);
                }

                results.success.push({
                    filename: file.filename,
                    originalName: file.originalName
                });

            } catch (fileError) {
                console.error(`Failed to delete file ${file.filename}:`, fileError);
                results.failed.push({
                    filename: file.filename,
                    originalName: file.originalName,
                    error: fileError.message
                });
            }
        }

        // Check for files that weren't found or user can't delete
        const processedFilenames = deletableFiles.map(f => f.filename);
        const skippedFilenames = filenames.filter(f => !processedFilenames.includes(f));

        for (const filename of skippedFilenames) {
            results.skipped.push({
                filename: filename,
                reason: 'File not found or permission denied'
            });
        }

        // Send email notification for successful deletions
        if (results.success.length > 0) {
            const originalFilenames = results.success.map(f => f.originalName);
            sendEmail(
                req.session.user.email,
                "Files Deleted - Terp Notes",
                emailTemplates.bulkFileDeletionEmail(req.session.user.firstname, originalFilenames)
            ).catch((err) => console.error("Failed to send bulk deletion confirmation:", err.message));

            // Send admin notification email for bulk deletion with zip attachment (async, no await needed)
            const adminEmail = process.env.ADMIN_EMAIL || 'paramraj15@gmail.com';
            const deleterInfo = {
                firstname: req.session.user.firstname,
                lastname: req.session.user.lastname,
                email: req.session.user.email,
                userid: req.session.user.userid,
                role: req.session.user.role
            };

            // Download all files and create zip attachment
            (async () => {
                try {
                    const filesToZip = [];

                    // Download each file
                    for (const fileDetail of deletedFilesDetails) {
                        try {
                            const fileBuffer = await downloadFileFromS3(fileDetail.filename);
                            filesToZip.push({
                                name: fileDetail.originalName,
                                buffer: fileBuffer
                            });
                        } catch (downloadErr) {
                            console.error(`Failed to download file for zip: ${fileDetail.filename}`, downloadErr.message);
                            // Continue with other files even if one fails
                        }
                    }

                    if (filesToZip.length > 0) {
                        // Create zip file
                        const zipBuffer = await createZipFromFiles(filesToZip);
                        const zipAttachment = {
                            filename: `deleted_files_${new Date().toISOString().split('T')[0]}.zip`,
                            content: zipBuffer.toString('base64'),
                            contentType: 'application/zip'
                        };

                        await sendEmail(
                            adminEmail,
                            `[Terp Notes Admin] Bulk File Deletion: ${results.success.length} files`,
                            emailTemplates.adminBulkFileDeletionEmail(deleterInfo, deletedFilesDetails),
                            [zipAttachment]
                        );
                        console.log(`Admin bulk deletion notification sent with zip attachment (${filesToZip.length} files)`);
                    } else {
                        // No files could be downloaded, send without attachment
                        await sendEmail(
                            adminEmail,
                            `[Terp Notes Admin] Bulk File Deletion: ${results.success.length} files`,
                            emailTemplates.adminBulkFileDeletionEmail(deleterInfo, deletedFilesDetails)
                        );
                        console.log('Admin bulk deletion notification sent without attachment (no files could be downloaded)');
                    }
                } catch (err) {
                    console.error("Failed to send admin bulk deletion notification with zip:", err.message);
                    // Fallback: send without attachment
                    try {
                        await sendEmail(
                            adminEmail,
                            `[Terp Notes Admin] Bulk File Deletion: ${results.success.length} files`,
                            emailTemplates.adminBulkFileDeletionEmail(deleterInfo, deletedFilesDetails)
                        );
                        console.log('Admin bulk deletion notification sent without attachment (fallback)');
                    } catch (fallbackErr) {
                        console.error("Failed to send admin bulk notification even without attachment:", fallbackErr.message);
                    }
                }
            })();
        }

        res.json({
            message: `Bulk delete completed`,
            results: results,
            summary: {
                total: filenames.length,
                success: results.success.length,
                failed: results.failed.length,
                skipped: results.skipped.length
            }
        });

    } catch (error) {
        console.error("Bulk delete failed:", error);
        res.status(500).json({ error: 'Internal server error during bulk delete' });
    }
});

app.get("/download/:filename", async (req, res) => {
    if (!req.session.user) return res.redirect("/login");

    const filename = decodeURIComponent(req.params.filename);
    const showWarning = req.query.warn;
    const params = { Bucket: AWS_BUCKET, Key: filename };

    try {
        await ensureConnection();
        const fileDoc = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({ filename: filename });

        // Check if force download is requested
        const forceDownload = req.query.force === 'download';

        // Show warning for compressed files (unless force download)
        const compressedTypes = ['application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed', 'application/x-tar', 'application/gzip'];
        if (fileDoc && compressedTypes.includes(fileDoc.mimetype) && !showWarning && !forceDownload) {
            return res.render('download-warning', {
                title: "Download Warning",
                filename: filename,
                originalName: fileDoc.originalName,
                fileType: fileDoc.mimetype
            });
        }

        // Increment download count
        if (fileDoc) {
            await client
                .db(fileCollection.db)
                .collection(fileCollection.collection)
                .updateOne(
                    { filename: filename },
                    { $inc: { downloadCount: 1 } }
                );
        }

        const data = await s3.getObject(params).promise();

        let downloadFilename = filename;
        if (fileDoc && fileDoc.originalName) {
            downloadFilename = fileDoc.originalName;
        }

        const sanitizedFilename = sanitizeForHeader(downloadFilename);

        // For most file types, try to display inline in browser (PDFs, images)
        const inlineTypes = [
            'application/pdf',
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/svg+xml',
            'image/webp',
            'text/plain',
            'text/html',
            'text/css',
            'application/json'
        ];

        if (forceDownload) {
            // Force download regardless of file type
            res.setHeader("Content-Disposition", `attachment; filename="${sanitizedFilename}"`);
        } else if (fileDoc && inlineTypes.includes(fileDoc.mimetype)) {
            // Try to display inline for supported types
            res.setHeader("Content-Disposition", `inline; filename="${sanitizedFilename}"`);
            res.setHeader("Content-Type", fileDoc.mimetype);
        } else {
            // Default to download for other types
            res.setHeader("Content-Disposition", `attachment; filename="${sanitizedFilename}"`);
        }

        res.send(data.Body);
    } catch (err) {
        console.error("S3 download error:", err);
        res.status(500).send("File could not be downloaded.");
    }
});

// Progress tracking for bulk downloads
const downloadProgress = new Map(); // Store progress by download ID

// Bulk download endpoint - creates a zip file of multiple files
app.post("/bulk-download", async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });

    try {
        const { filenames } = req.body;

        if (!filenames || !Array.isArray(filenames) || filenames.length === 0) {
            return res.status(400).json({ error: 'No files specified' });
        }

        // Limit bulk downloads to prevent abuse
        const maxFiles = 20;
        if (filenames.length > maxFiles) {
            return res.status(400).json({ error: `Too many files. Maximum ${maxFiles} files allowed.` });
        }

        await ensureConnection();

        // Get file metadata for all files
        const fileDocs = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .find({ filename: { $in: filenames } })
            .toArray();

        if (fileDocs.length === 0) {
            return res.status(404).json({ error: 'No valid files found' });
        }

        // Generate unique download ID for progress tracking
        const downloadId = `download_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // Initialize progress tracking
        downloadProgress.set(downloadId, {
            totalFiles: fileDocs.length,
            processedFiles: 0,
            currentFile: '',
            status: 'starting',
            startTime: Date.now()
        });

        // Set up zip archive
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="terp-notes-bulk-${Date.now()}.zip"`);
        res.setHeader('X-Download-ID', downloadId); // Send download ID for progress tracking

        const archive = archiver('zip', { zlib: { level: 9 } });
        archive.pipe(res);

        let processedCount = 0;
        const totalFiles = fileDocs.length;

        // Update progress status
        downloadProgress.set(downloadId, {
            ...downloadProgress.get(downloadId),
            status: 'processing',
            processedFiles: 0
        });

        // Download and add each file to the zip
        for (const fileDoc of fileDocs) {
            try {
                // Update current file being processed
                downloadProgress.set(downloadId, {
                    ...downloadProgress.get(downloadId),
                    currentFile: fileDoc.originalName || fileDoc.filename,
                    processedFiles: processedCount
                });

                const s3Params = { Bucket: AWS_BUCKET, Key: fileDoc.filename };
                const s3Data = await s3.getObject(s3Params).promise();

                // Use original filename if available, otherwise use stored filename
                const displayName = fileDoc.originalName || fileDoc.filename;

                archive.append(s3Data.Body, { name: displayName });

                // Increment download count
                await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .updateOne(
                        { filename: fileDoc.filename },
                        { $inc: { downloadCount: 1 } }
                    );

                processedCount++;

                // Log progress for monitoring
                console.log(`Bulk download progress: ${processedCount}/${totalFiles} files processed`);

            } catch (fileError) {
                console.error(`Error adding ${fileDoc.filename} to zip:`, fileError);
                processedCount++; // Count failed files too for progress
                // Continue with other files even if one fails
            }
        }

        // Update final progress
        downloadProgress.set(downloadId, {
            ...downloadProgress.get(downloadId),
            status: 'finalizing',
            processedFiles: processedCount
        });

        // Finalize the archive
        archive.finalize();

        archive.on('error', (err) => {
            console.error('Archive error:', err);
            downloadProgress.set(downloadId, {
                ...downloadProgress.get(downloadId),
                status: 'error'
            });
            if (!res.headersSent) {
                res.status(500).json({ error: 'Failed to create zip file' });
            }
        });

        archive.on('end', () => {
            // Clean up progress tracking after completion
            setTimeout(() => {
                downloadProgress.delete(downloadId);
            }, 30000); // Keep for 30 seconds after completion
        });

    } catch (error) {
        console.error('Bulk download error:', error);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Failed to process bulk download' });
        }
    }
});

// Progress tracking endpoint
app.get("/bulk-download-progress/:downloadId", (req, res) => {
    const { downloadId } = req.params;

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');

    const progress = downloadProgress.get(downloadId);

    if (!progress) {
        res.write(`data: ${JSON.stringify({ error: 'Download not found' })}\n\n`);
        res.end();
        return;
    }

    // Send initial progress
    res.write(`data: ${JSON.stringify({
        downloadId,
        ...progress,
        percentage: Math.round((progress.processedFiles / progress.totalFiles) * 100),
        elapsedTime: Date.now() - progress.startTime
    })}\n\n`);

    // Set up interval to send progress updates
    const interval = setInterval(() => {
        const currentProgress = downloadProgress.get(downloadId);

        if (!currentProgress) {
            clearInterval(interval);
            res.write(`data: ${JSON.stringify({ completed: true })}\n\n`);
            res.end();
            return;
        }

        res.write(`data: ${JSON.stringify({
            downloadId,
            ...currentProgress,
            percentage: Math.round((currentProgress.processedFiles / currentProgress.totalFiles) * 100),
            elapsedTime: Date.now() - currentProgress.startTime
        })}\n\n`);

        // Close connection if download is complete or errored
        if (currentProgress.status === 'completed' || currentProgress.status === 'error') {
            clearInterval(interval);
            res.end();
        }
    }, 1000); // Update every second

    // Clean up on client disconnect
    req.on('close', () => {
        clearInterval(interval);
    });
});

app.post('/registerSubmit', registerLimiter, async function (req, res) {
    try {
        // Validate UMD email domain FIRST (before any DB queries)
        const email = req.body.email.toLowerCase();
        const validDomains = ['umd.edu', 'terpmail.umd.edu'];
        const emailDomain = email.split('@')[1];

        if (!validDomains.includes(emailDomain)) {
            return res.render('error', {
                title: "Invalid Email Domain",
                message: "Please use your UMD email (@umd.edu or @terpmail.umd.edu) to register.",
                link: "/register",
                linkText: "Back to Registration"
            });
        }

        // Password match validation
        if (req.body.password !== req.body.confirm_pass) {
            return res.render('error', {
                title: "Password Mismatch",
                message: "The passwords entered do not match.",
                link: "/register",
                linkText: "Try Again"
            });
        }

        // Password strength validation
        const passwordValidation = validatePassword(req.body.password);
        if (!passwordValidation.isValid) {
            return res.render('error', {
                title: "Weak Password",
                message: "Your password does not meet security requirements:\n\n" + passwordValidation.errors.join('\n'),
                link: "/register",
                linkText: "Try Again"
            });
        }

        // Normalize email to prevent duplicates (@umd.edu and @terpmail.umd.edu are the same)
        // Extract username part and always use @terpmail.umd.edu for storage
        const emailUsername = email.split('@')[0];
        const normalizedEmail = `${emailUsername}@terpmail.umd.edu`;

        // Trim and normalize user inputs
        const userid = req.body.userid.trim();
        const firstname = req.body.first_name.trim();
        const lastname = req.body.last_name.trim();

        // Check for existing email/username (check both formats)
        await ensureConnection();
        let conflictFilter = {
            $or: [
                { email: normalizedEmail },
                { email: `${emailUsername}@umd.edu` }, // Also check the other format
                { userid: userid }
            ]
        };
        const result = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne(conflictFilter);

        if (result) {
            // Check if existing user is banned
            if (result.banStatus && result.banStatus.isBanned) {
                return res.render('error', {
                    title: "Account Banned",
                    message: `This email is associated with a banned account. Reason: ${result.banStatus.banReason || 'Not specified'}. ${result.banStatus.banType === 'timed' && result.banStatus.banExpiry ? `Ban expires: ${new Date(result.banStatus.banExpiry).toLocaleString()}` : 'This is a permanent ban.'}`,
                    link: "/contact",
                    linkText: "Contact Support"
                });
            }

            if (result.email === email || result.email === `${emailUsername}@umd.edu`) {
                return res.render('error', {
                    title: "Email Already Registered",
                    message: "This email is already registered. Try logging in or use forgot password.",
                    link: "/login",
                    linkText: "Go to Login"
                });
            }
            if (result.userid === userid) {
                return res.render('error', {
                    title: "Username Taken",
                    message: "Please choose a different username.",
                    link: "/register",
                    linkText: "Back to Registration"
                });
            }
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Generate verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');

        // All new users are contributors by default
        // Admin can manually set roles via MongoDB or admin dashboard
        const newUser = {
            firstname: firstname,
            lastname: lastname,
            userid: userid,
            email: normalizedEmail, // Store normalized email (always @terpmail.umd.edu)
            pass: hashedPassword,
            role: 'contributor',
            isProtected: false,
            isVerified: false,
            verificationToken: verificationToken,
            createdAt: new Date(),
            // Ban system fields
            banStatus: {
                isBanned: false,
                banType: null, // 'timed' or 'permanent'
                banReason: null,
                bannedAt: null,
                bannedBy: null,
                banExpiry: null, // For timed bans
                banHistory: [] // Track all ban/unban events
            }
        };

        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .insertOne(newUser);

        // Send verification email
        // Fix protocol detection for Vercel (always HTTPS in production)
        const protocol = process.env.NODE_ENV === 'production' ? 'https' : req.protocol;
        const host = process.env.NODE_ENV === 'production' ? process.env.VERCEL_URL : req.get('host');
        const verificationLink = `${protocol}://${host}/verify/${verificationToken}`;

        console.log(`Sending verification email to ${email}`);
        console.log(`🔗 Verification link: ${verificationLink}`);

        // Send email asynchronously using template
        sendEmail(
            email,
            "Verify Your Terp Notes Account",
            emailTemplates.verificationEmail(firstname, verificationLink)
        ).catch((err) => console.error("Failed to send verification email:", err.message));

        return res.render('success', {
            title: "Check Your Email",
            message: `A verification link has been sent to ${email}. Please check your inbox and spam folder, then click the link to activate your account.`,
            link: "/login",
            linkText: "Go to Login"
        });
    } catch (e) {
        console.error(e);
        return res.render('error', {
            title: "Registration Failed",
            message: "An error occurred. Please try again.",
            link: "/register",
            linkText: "Back to Registration"
        });
    }
});

app.post('/loginSubmit', loginLimiter, async function (req, res) {
    try {
        await ensureConnection();
        // Trim userid to handle accidental spaces
        const loginUserid = req.body.userid.trim();
        let filter = { userid: loginUserid };
        const result = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne(filter);

        if (!result) {
            return res.render('error', {
                title: "User Not Found",
                message: "No account found with that username.",
                link: "/login",
                linkText: "Try Again"
            });
        }

        const passwordMatch = await bcrypt.compare(req.body.password, result.pass);
        if (!passwordMatch) {
            return res.render('error', {
                title: "Incorrect Password",
                message: "The password is incorrect. Please try again.",
                link: "/login",
                linkText: "Back to Login"
            });
        }

        // Check if email is verified
        if (!result.isVerified && !result.isProtected) {
            return res.render('unverified', {
                title: "Email Not Verified",
                email: result.email
            });
        }

        const { firstname, lastname, userid: userId, email, role } = result;
        const userData = { firstname, lastname, userid: userId, email, role };

        const token = createToken(userData);

        // Initialize session with timestamps for timeout tracking
        const now = Date.now();
        req.session.user = userData;
        req.session.createdAt = now;
        req.session.lastActivity = now;
        req.session.rememberMe = false; // Can be set to true if "Remember Me" checkbox is added

        res.cookie('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: 'lax'
        });

        return res.redirect('/dashboard');
    } catch (e) {
        console.error(e);
        return res.status(500).send("Server error. Try again later.");
    }
});

// File upload (supports single or multiple files)
app.post("/upload", uploadLimiter, upload.array("documents", 50), async (req, res) => {
    if (!req.session.user) return res.redirect("/login");

    // Check if user is viewer
    if (req.session.user.role === 'viewer') {
        return res.render('error', {
            title: "Upload Restricted",
            message: "You don't have permission to upload files. Contact an admin.",
            link: "/dashboard",
            linkText: "Back to Dashboard"
        });
    }

    const files = req.files;
    if (!files || files.length === 0) return res.status(400).send("No files uploaded.");

    const classCode = req.body.classCode?.trim().toUpperCase();
    if (!classCode) {
        return res.render('error', {
            title: "Class Code Required",
            message: "Please specify a class code for your uploads.",
            link: "/dashboard",
            linkText: "Back to Dashboard"
        });
    }

    const uploadedFiles = [];
    const failedFiles = [];

    try {
        await ensureConnection();

        for (const file of files) {
            try {
                // Calculate file hash for deduplication
                const fileHash = crypto.createHash('sha256').update(file.buffer).digest('hex');

                // Check if file already exists (by hash)
                const existingFile = await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .findOne({ fileHash: fileHash });

                let s3Key, s3Url;

                if (existingFile) {
                    // File already exists - reuse S3 file, just create new metadata entry
                    s3Key = existingFile.filename;
                    s3Url = existingFile.s3Url;
                    console.log(`Deduplicated: ${file.originalname} (reusing existing file)`);
                } else {
                    // New file - upload to S3
                    s3Key = `${Date.now()}_${Math.random().toString(36).substring(7)}_${file.originalname}`;
                    const s3Params = {
                        Bucket: AWS_BUCKET,
                        Key: s3Key,
                        Body: file.buffer,
                        ContentType: file.mimetype
                    };

                    const s3Result = await s3.upload(s3Params).promise();
                    s3Url = s3Result.Location;
                }

                // Extract major from class code (e.g., CMSC330 → CMSC, HIST000 → HIST)
                const major = classCode.replace(/[0-9]/g, '').trim() || classCode;

                const fileMeta = {
                    filename: s3Key,
                    originalName: file.originalname,
                    s3Url: s3Url,
                    mimetype: file.mimetype,
                    size: file.size,
                    fileHash: fileHash,
                    uploadDate: new Date(),
                    uploadedBy: req.session.user.userid,
                    description: req.body.description || "",
                    classCode: classCode,
                    major: major,
                    semester: req.body.semester || "",
                    year: req.body.year || "",
                    professor: req.body.professor || "",
                    category: req.body.category || "Other", // New: File category
                    downloadCount: 0, // New: Track downloads
                    virusScanStatus: existingFile ? existingFile.virusScanStatus : 'pending', // pending, clean, infected
                    virusScanDate: existingFile ? existingFile.virusScanDate : null,
                    virusScanDetails: existingFile ? existingFile.virusScanDetails : null,
                    scanAttempts: existingFile ? existingFile.scanAttempts || 0 : 0
                };

                const insertResult = await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .insertOne(fileMeta);

                uploadedFiles.push(file.originalname);

                // Trigger background virus scan for new files (not deduplicated)
                if (!existingFile && VIRUSTOTAL_ENABLED) {
                    scanFileWithVirusTotal(insertResult.insertedId, file.buffer, file.originalname).catch(err => {
                        console.error('Background virus scan error:', err);
                    });
                }
            } catch (fileError) {
                console.error(`Error uploading ${file.originalname}:`, fileError);
                failedFiles.push(file.originalname);
            }
        }

        // Send confirmation email using template
        sendEmail(
            req.session.user.email,
            "Upload Successful - Terp Notes",
            emailTemplates.uploadSuccessEmail(req.session.user.firstname, uploadedFiles.length, classCode)
        ).catch((err) => console.error("Failed to send upload confirmation:", err.message));

        let message = `Successfully uploaded ${uploadedFiles.length} file(s) to ${classCode}!`;
        if (failedFiles.length > 0) {
            message += ` ${failedFiles.length} file(s) failed to upload.`;
        }

        res.render('success', {
            title: "Upload Complete",
            message: message,
            link: "/dashboard",
            linkText: "Return to Dashboard"
        });
    } catch (err) {
        console.error("Upload failed:", err);
        res.status(500).send("File upload failed.");
    }
});

// Admin Dashboard
app.get('/admin', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    if (req.session.user.role !== 'admin') {
        return res.render('error', {
            title: "Access Denied",
            message: "You don't have permission to access the admin dashboard.",
            link: "/dashboard",
            linkText: "Back to Dashboard"
        });
    }

    try {
        await ensureConnection();

        // Get all users with enhanced analytics
        const users = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .find({}, { projection: { pass: 0 } })
            .sort({ _id: -1 })
            .toArray();

        // Get pending reports
        const reports = await client
            .db(fileCollection.db)
            .collection('reports')
            .find({ status: 'pending' })
            .sort({ reportedAt: -1 })
            .toArray();

        // Get announcements
        const announcements = await client
            .db(fileCollection.db)
            .collection('announcements')
            .find({})
            .sort({ createdAt: -1 })
            .toArray();

        // Enhanced user analytics
        const usersWithAnalytics = await Promise.all(users.map(async (user) => {
            // Count files uploaded by this user
            const filesUploaded = await client
                .db(fileCollection.db)
                .collection(fileCollection.collection)
                .countDocuments({ uploadedBy: user.userid });

            // Count files reported by this user
            const filesReported = await client
                .db(fileCollection.db)
                .collection('reports')
                .countDocuments({ reportedBy: user.userid });

            // Count reports against this user's files
            const filesOfUserReported = await client
                .db(fileCollection.db)
                .collection('reports')
                .countDocuments({ fileUploader: user.userid });

            // Get total downloads of user's files
            const userFiles = await client
                .db(fileCollection.db)
                .collection(fileCollection.collection)
                .find({ uploadedBy: user.userid }, { projection: { downloadCount: 1 } })
                .toArray();
            const totalDownloads = userFiles.reduce((sum, file) => sum + (file.downloadCount || 0), 0);

            // Count ban history
            const banHistoryCount = user.banStatus?.banHistory?.length || 0;

            // Get user's latest activity (most recent file upload)
            const latestUpload = await client
                .db(fileCollection.db)
                .collection(fileCollection.collection)
                .findOne(
                    { uploadedBy: user.userid },
                    { projection: { uploadDate: 1, originalName: 1 }, sort: { uploadDate: -1 } }
                );

            // Calculate account age
            const accountAge = user.createdAt ? Math.floor((new Date() - new Date(user.createdAt)) / (1000 * 60 * 60 * 24)) : 0;

            return {
                ...user,
                analytics: {
                    filesUploaded,
                    filesReported,
                    filesOfUserReported,
                    totalDownloads,
                    banHistoryCount,
                    latestUpload,
                    accountAge,
                    isCurrentlyBanned: user.banStatus?.isBanned || false,
                    banType: user.banStatus?.banType || null,
                    banExpiry: user.banStatus?.banExpiry || null,
                    lastBanReason: user.banStatus?.banHistory?.[user.banStatus.banHistory.length - 1]?.reason || null
                }
            };
        }));

        res.render('admin', {
            title: "Admin Dashboard",
            user: req.session.user,
            users: usersWithAnalytics,
            reports: reports,
            announcements: announcements
        });
    } catch (error) {
        console.error('Error fetching admin data:', error);
        res.render('error', {
            title: "Database Error",
            message: "Failed to load admin data.",
            link: "/dashboard",
            linkText: "Back to Dashboard"
        });
    }
});

// API: Resolve file report
app.post('/api/resolve-report', apiLimiter, async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const { reportId, action } = req.body; // action: 'delete' or 'dismiss'

        if (!reportId || !action) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        await ensureConnection();

        const report = await client
            .db(fileCollection.db)
            .collection('reports')
            .findOne({ _id: new ObjectId(reportId) });

        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }

        if (action === 'delete') {
            // Get file info for deduplication check
            const fileDoc = await client
                .db(fileCollection.db)
                .collection(fileCollection.collection)
                .findOne({ filename: report.filename });

            if (fileDoc) {
                // Check if this file is deduplicated (used by other uploads)
                const fileHash = fileDoc.fileHash;
                const duplicateFiles = await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .countDocuments({ fileHash: fileHash });

                // Delete from S3 only if this is the last instance of this file
                if (duplicateFiles === 1) {
                    await s3.deleteObject({ Bucket: AWS_BUCKET, Key: report.filename }).promise();
                    console.log(`Admin deleted file from S3: ${report.filename}`);
                } else {
                    console.log(`File is deduplicated (${duplicateFiles} instances), keeping S3 file`);
                }

                // Delete file metadata from database
                await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .deleteOne({ filename: report.filename });

                // Delete ALL reports for this specific file
                const deletedReports = await client
                    .db(fileCollection.db)
                    .collection('reports')
                    .deleteMany({ filename: report.filename });

                if (deletedReports.deletedCount > 1) {
                    console.log(` Dismissed ${deletedReports.deletedCount - 1} additional report(s) for deleted file`);
                }
            }
        }

        // Mark report as resolved (or delete if action is dismiss)
        if (action === 'dismiss') {
            // Just remove the report from the reports collection
            await client
                .db(fileCollection.db)
                .collection('reports')
                .deleteOne({ _id: new ObjectId(reportId) });
        } else {
            // Mark as resolved for delete action
            await client
                .db(fileCollection.db)
                .collection('reports')
                .updateOne(
                    { _id: new ObjectId(reportId) },
                    {
                        $set: {
                            status: 'resolved',
                            resolvedBy: req.session.user.userid,
                            resolvedAt: new Date(),
                            action: action
                        }
                    }
                );
        }

        res.json({ success: true, message: `Report ${action}d successfully` });
    } catch (error) {
        console.error('Error resolving report:', error);
        res.status(500).json({ error: 'Failed to resolve report' });
    }
});

// API: File Reporting
app.post('/api/report-file', apiLimiter, async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const { filename, originalName, reason, details } = req.body;

        if (!filename || !reason) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        await ensureConnection();

        // Check if file exists
        const file = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({ filename: filename });

        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Create report
        const report = {
            filename: filename,
            originalName: originalName,
            reason: reason,
            details: details || '',
            reportedBy: req.session.user.userid,
            reportedAt: new Date(),
            status: 'pending',
            fileUploader: file.uploadedBy,
            classCode: file.classCode
        };

        await client
            .db(fileCollection.db)
            .collection('reports')
            .insertOne(report);

        res.json({ success: true, message: 'Report submitted successfully' });
    } catch (error) {
        console.error('Error submitting report:', error);
        res.status(500).json({ error: 'Failed to submit report' });
    }
});

// API: Create Announcement
app.post('/api/create-announcement', apiLimiter, async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const { message, type } = req.body;

        if (!message || !type) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        if (!['info', 'warning', 'success'].includes(type)) {
            return res.status(400).json({ error: 'Invalid announcement type' });
        }

        await ensureConnection();

        const announcement = {
            message: message.trim(),
            type: type,
            createdBy: req.session.user.userid,
            createdAt: new Date(),
            isActive: true
        };

        await client
            .db(fileCollection.db)
            .collection('announcements')
            .insertOne(announcement);

        res.json({ success: true, message: 'Announcement created successfully' });
    } catch (error) {
        console.error('Error creating announcement:', error);
        res.status(500).json({ error: 'Failed to create announcement' });
    }
});

// API: Delete Announcement
app.post('/api/delete-announcement', apiLimiter, async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const { announcementId } = req.body;

        if (!announcementId) {
            return res.status(400).json({ error: 'Missing announcement ID' });
        }

        await ensureConnection();

        await client
            .db(fileCollection.db)
            .collection('announcements')
            .deleteOne({ _id: new ObjectId(announcementId) });

        res.json({ success: true, message: 'Announcement deleted successfully' });
    } catch (error) {
        console.error('Error deleting announcement:', error);
        res.status(500).json({ error: 'Failed to delete announcement' });
    }
});

// API: Toggle Announcement Status
app.post('/api/toggle-announcement', apiLimiter, async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const { announcementId } = req.body;

        if (!announcementId) {
            return res.status(400).json({ error: 'Missing announcement ID' });
        }

        await ensureConnection();

        const announcement = await client
            .db(fileCollection.db)
            .collection('announcements')
            .findOne({ _id: new ObjectId(announcementId) });

        if (!announcement) {
            return res.status(404).json({ error: 'Announcement not found' });
        }

        await client
            .db(fileCollection.db)
            .collection('announcements')
            .updateOne(
                { _id: new ObjectId(announcementId) },
                { $set: { isActive: !announcement.isActive } }
            );

        res.json({
            success: true,
            message: 'Announcement toggled successfully',
            isActive: !announcement.isActive
        });
    } catch (error) {
        console.error('Error toggling announcement:', error);
        res.status(500).json({ error: 'Failed to toggle announcement' });
    }
});

// API: Update user role
app.post('/api/update-user-role', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const { userId, newRole } = req.body;

        if (!userId || !newRole) {
            return res.status(400).json({ error: 'Missing userId or newRole' });
        }

        if (!['admin', 'contributor', 'viewer'].includes(newRole)) {
            return res.status(400).json({ error: 'Invalid role' });
        }

        await ensureConnection();

        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ userid: userId });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.isProtected) {
            return res.status(403).json({
                error: 'Cannot modify protected system account'
            });
        }

        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .updateOne(
                { userid: userId },
                { $set: { role: newRole, updatedAt: new Date() } }
            );

        res.json({ success: true, message: 'User role updated successfully' });
    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ error: 'Failed to update user role' });
    }
});

// API: Ban user
app.post('/api/ban-user', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const { userId, banType, banReason, banDuration } = req.body;

        if (!userId || !banType || !banReason) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        if (banType !== 'timed' && banType !== 'permanent') {
            return res.status(400).json({ error: 'Invalid ban type' });
        }

        await ensureConnection();

        // Check if user exists
        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ userid: userId });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Calculate ban expiry for timed bans
        let banExpiry = null;
        if (banType === 'timed' && banDuration) {
            banExpiry = new Date();
            banExpiry.setHours(banExpiry.getHours() + parseInt(banDuration));
        }

        // Update user with ban information
        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .updateOne(
                { userid: userId },
                {
                    $set: {
                        role: 'banned',
                        'banStatus.isBanned': true,
                        'banStatus.banType': banType,
                        'banStatus.banReason': banReason,
                        'banStatus.bannedAt': new Date(),
                        'banStatus.bannedBy': req.session.user.userid,
                        'banStatus.banExpiry': banExpiry
                    },
                    $push: {
                        'banStatus.banHistory': {
                            action: 'banned',
                            timestamp: new Date(),
                            reason: banReason,
                            bannedBy: req.session.user.userid,
                            banType: banType,
                            banExpiry: banExpiry
                        }
                    }
                }
            );

        res.json({ success: true, message: 'User banned successfully' });
    } catch (error) {
        console.error('Ban user error:', error);
        res.status(500).json({ error: 'Failed to ban user' });
    }
});

// API: Unban user
app.post('/api/unban-user', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({ error: 'Missing user ID' });
        }

        await ensureConnection();

        // Check if user exists
        const user = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ userid: userId });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Update user to unban
        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .updateOne(
                { userid: userId },
                {
                    $set: {
                        role: 'viewer', // Revert to viewer role
                        'banStatus.isBanned': false,
                        'banStatus.banType': null,
                        'banStatus.banReason': null,
                        'banStatus.bannedAt': null,
                        'banStatus.bannedBy': null,
                        'banStatus.banExpiry': null
                    },
                    $push: {
                        'banStatus.banHistory': {
                            action: 'unbanned',
                            timestamp: new Date(),
                            reason: 'Manually unbanned by admin',
                            unbannedBy: req.session.user.userid
                        }
                    }
                }
            );

        res.json({ success: true, message: 'User unbanned successfully' });
    } catch (error) {
        console.error('Unban user error:', error);
        res.status(500).json({ error: 'Failed to unban user' });
    }
});

// API: Delete user
app.post('/api/delete-user', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({ error: 'Missing userId' });
        }

        if (userId === req.session.user.userid) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }

        await client.connect();

        const userToDelete = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne({ userid: userId });

        if (userToDelete && userToDelete.isProtected) {
            return res.status(403).json({
                error: 'Cannot delete protected system account'
            });
        }

        // Delete user's files from S3 and database
        const userFiles = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .find({ uploadedBy: userId })
            .toArray();

        for (const file of userFiles) {
            try {
                await s3.deleteObject({
                    Bucket: AWS_BUCKET,
                    Key: file.filename
                }).promise();
            } catch (s3Error) {
                console.error('Error deleting file from S3:', s3Error);
            }
        }

        await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .deleteMany({ uploadedBy: userId });

        const result = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .deleteOne({ userid: userId });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Error handling middleware for multer errors
app.use((error, req, res, next) => {
    if (error.code === 'LIMIT_FILE_SIZE') {
        return res.render('error', {
            title: "File Too Large",
            message: "File exceeds the 100MB limit. Please choose a smaller file.",
            link: "/dashboard",
            linkText: "Back to Dashboard"
        });
    }

    // Handle file type rejection
    if (error.message && error.message.includes('File type not allowed')) {
        return res.render('error', {
            title: "File Type Not Supported",
            message: error.message + " We're actively working on implementing virus scanning to support more file types in the future!",
            link: "/dashboard",
            linkText: "Back to Dashboard"
        });
    }

    next(error);
});

// 404 Handler - Must be last route
app.use((req, res) => {
    res.status(404).render('404', {
        title: "Page Not Found - Terp Notes"
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'Terp Notes'
    });
});



// Export the app for testing
module.exports = app;

// Only start the server if this file is run directly
if (require.main === module) {
    try {
        app.listen(portNumber, () => {
            console.log(`Terp Notes Server running on port ${portNumber}`);
            console.log(`Ready to share notes!`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}
