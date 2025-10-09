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
    console.log('🛡️ VirusTotal integration enabled');
} else {
    console.log('⚠️ VirusTotal integration disabled (no API key found)');
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
console.log(`🐢 Terp Notes Server starting on port ${portNumber}`);

/* Express Setup */
const express = require("express");
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
const FormData = require('form-data');
const app = express();

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
app.use((req, res, next) => {
    const publicRoutes = ['/', '/login', '/register', '/loginSubmit', '/registerSubmit', '/forgot-password', '/resend-verification', '/privacy', '/terms', '/contact', '/contact/submit'];
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

    next();
});

/* Email Handling */
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Test email configuration on startup
console.log('📧 Email Configuration:');
console.log('   EMAIL_USER:', process.env.EMAIL_USER ? 'Set' : 'Missing');
console.log('   EMAIL_PASS:', process.env.EMAIL_PASS ? 'Set' : 'Missing');
console.log('   NODE_ENV:', process.env.NODE_ENV || 'development');
console.log('   VERCEL_URL:', process.env.VERCEL_URL || 'Not set');

/* Password Hashing */
const bcrypt = require('bcrypt');

/* File Hashing for Deduplication */
const crypto = require('crypto');

// No default accounts created
// All users register as contributors
console.log('📝 No default accounts - manually set admin via MongoDB');

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

        console.log('📊 Database indexes created successfully');
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
                uploadDate: { $lt: tenMinutesAgo }
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

    try {
        console.log(`🔍 Starting virus scan for: ${filename}`);

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

        console.log(`⏳ File uploaded to VirusTotal. Analysis ID: ${analysisId}`);

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

                console.log(`✅ Scan complete for ${filename}: ${malicious} malicious, ${suspicious} suspicious out of ${totalEngines} engines`);

                // Update file metadata
                await client.connect();

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
                            console.log(`🗑️ Deleted infected file from S3: ${filename}`);
                        } catch (s3Error) {
                            console.error('Error deleting infected file from S3:', s3Error);
                        }

                        // Delete metadata
                        await client
                            .db(fileCollection.db)
                            .collection(fileCollection.collection)
                            .deleteOne({ _id: fileId });

                        console.log(`⚠️ INFECTED FILE REMOVED: ${filename} (${malicious} detections)`);
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

                    console.log(`✅ File marked as clean: ${filename}`);
                }

                await client.close();
            } else {
                retries++;
                console.log(`⏳ Scan in progress (${retries}/${maxRetries})...`);
            }
        }

        if (!scanComplete) {
            console.log(`⚠️ Scan timeout for ${filename}, will remain as pending`);
        }

    } catch (error) {
        console.error(`❌ VirusTotal scan error for ${filename}:`, error.message);

        // On error, leave file as 'pending' - don't delete
        try {
            await client.connect();
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
                        }
                    }
                );
            await client.close();
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
    res.render('index', { title: "Terp Notes - UMD Resource Sharing" });
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
            await client.close();

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
        console.log(`🔍 [API] Fetching course data for: ${courseId}`);

        // Get query parameters for filtering
        const querySemester = req.query.filter_semester;
        const queryYear = req.query.filter_year;
        console.log(`🔍 [API] Filters - Semester: ${querySemester}, Year: ${queryYear}`);

        // Determine which semesters to fetch based on filters
        let semestersToCheck = [];

        if (querySemester && queryYear) {
            // Specific semester and year
            const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
            const semesterId = `${queryYear}${semesterMap[querySemester] || '01'}`;
            semestersToCheck = [semesterId];
            console.log(`🔍 [API] Fetching specific: ${querySemester} ${queryYear} (${semesterId})`);
        } else if (querySemester) {
            // All years for this semester
            const semesterMap = { 'Spring': '01', 'Summer': '05', 'Fall': '08', 'Winter': '12' };
            const semesterNum = semesterMap[querySemester] || '01';
            for (let year = 2020; year <= 2025; year++) {
                semestersToCheck.push(`${year}${semesterNum}`);
            }
            console.log(`🔍 [API] Fetching all years for ${querySemester}: ${semestersToCheck.length} semesters`);
        } else if (queryYear) {
            // All semesters for this year
            semestersToCheck = [`${queryYear}01`, `${queryYear}05`, `${queryYear}08`, `${queryYear}12`];
            console.log(`🔍 [API] Fetching all semesters for ${queryYear}: ${semestersToCheck.length} semesters`);
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
            console.log(`🔍 [API] Fetching current semester only: ${currentSemester} ${currentYear} (${currentSemesterId})`);
        }

        // Fetch course info from first semester to get basic course data
        const firstSemester = semestersToCheck[0];
        const courseData = await fetchUMDData(
            `/courses/${courseId}?semester=${firstSemester}`,
            `course_${courseId}_${firstSemester}`,
            7 * 24 * 60 * 60 * 1000
        );

        if (!courseData || courseData.length === 0) {
            console.log(`❌ [API] Course not found: ${courseId}`);
            return res.status(404).json({ error: 'Course not found' });
        }

        const course = courseData[0];
        console.log(`✅ [API] Course found: ${course.name || courseId}`);

        // Fetch professor data for all required semesters
        const historicalData = {};
        const allProfessors = new Set();
        const allSemesters = new Set();
        const allYears = new Set();

        console.log(`🔍 [API] Fetching professor data for ${semestersToCheck.length} semester(s)...`);

        for (const semester of semestersToCheck) {
            try {
                console.log(`🔍 [API] Fetching sections for semester: ${semester}`);
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

                        console.log(`✅ [API] Found ${professors.length} professors for ${semesterName} ${year}: ${professors.join(', ')}`);
                    } else {
                        console.log(`⚠️ [API] No professors found for ${semester}`);
                    }
                } else {
                    console.log(`⚠️ [API] No sections found for ${semester}`);
                }
            } catch (error) {
                console.log(`❌ [API] Error fetching data for ${semester}:`, error.message);
            }
        }

        // Convert Sets to Arrays and sort
        const professorList = [...allProfessors].sort();
        const semesterList = [...allSemesters].sort();
        const yearList = [...allYears].sort((a, b) => b - a);

        console.log(`📊 [API] Final results:`);
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
        console.error('❌ [API] Error fetching course details:', error);
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
            await client.close();

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
        description
    } = req.body;

    if (!s3Key || !s3Url || !filename || !classCode || !fileHash) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        await client.connect();

        // Check for duplicates
        const existingFile = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({ fileHash: fileHash });

        if (existingFile) {
            // Delete newly uploaded file from S3 (it's a duplicate)
            await s3.deleteObject({ Bucket: AWS_BUCKET, Key: s3Key }).promise();

            return res.json({
                success: true,
                duplicate: true,
                message: 'File already exists',
                existingFile: existingFile
            });
        }

        // Save file metadata
        const fileMeta = {
            filename: s3Key,
            originalName: filename,
            s3Url: s3Url,
            mimetype: filetype,
            size: filesize,
            fileHash: fileHash,
            uploadDate: new Date(),
            uploadedBy: req.session.user.userid,
            description: description || "",
            classCode: classCode.trim().toUpperCase(),
            major: major || classCode.replace(/[0-9]/g, '').trim(),
            semester: semester || "",
            year: year || "",
            professor: professor || "",
            virusScanStatus: 'pending',
            virusScanDate: null,
            virusScanDetails: null
        };

        const insertResult = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .insertOne(fileMeta);

        // Trigger background virus scan (download from S3 asynchronously)
        if (VIRUSTOTAL_ENABLED) {
            s3.getObject({ Bucket: AWS_BUCKET, Key: s3Key }).promise()
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
            message: 'File uploaded successfully'
        });
    } catch (error) {
        console.error('Confirm upload error:', error);
        res.status(500).json({ error: 'Failed to save file metadata' });
    } finally {
        await client.close();
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

        // Send email to admin
        const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: adminEmail,
            replyTo: email,
            subject: `[Terp Notes Support] ${subject}`,
            text: `
Support Request from Terp Notes

Name: ${name}
Email: ${email}
Subject: ${subject}

Message:
${message}

---
Sent via Terp Notes Contact Form
            `
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error("Error sending contact email:", err);
            } else {
                console.log('Contact form submitted:', email);
            }
        });

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
        await client.connect();

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

        console.log(`📧 Sending password reset email to ${email}`);
        console.log(`🔗 Reset link: ${resetLink}`);
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.body.email,
            subject: "Reset Your Terp Notes Password",
            html: `
                <h2>Password Reset Request</h2>
                <p>Hello ${user.firstname},</p>
                <p>We received a request to reset your Terp Notes password. Click the button below to create a new password:</p>
                <p><a href="${resetLink}" style="background: #E03A3C; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">Reset Password</a></p>
                <p>Or copy this link: ${resetLink}</p>
                <p><strong>This link will expire in 1 hour.</strong></p>
                <p><small>If you didn't request this, please ignore this email. Your password will not be changed.</small></p>
                <hr style="margin: 2rem 0; border: none; border-top: 1px solid #E5E7EB;">
                <p style="color: #6B7280; font-size: 0.875rem;">
                    <strong>Terp Notes</strong> - Built for Terps, by Terps<br>
                    <em>Not affiliated with, endorsed by, or officially connected to the University of Maryland.</em>
                </p>
            `
        };
        transporter.sendMail(mailOptions, (err) => {
            if (err) console.error("Error sending reset email:", err);
        });

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
    } finally {
        await client.close();
    }
});

app.get('/reset-password/:token', async (req, res) => {
    const token = req.params.token;

    try {
        await client.connect();

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
    } finally {
        await client.close();
    }
});

app.post('/reset-password/:token', async (req, res) => {
    const token = req.params.token;

    try {
        await client.connect();

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

        // Send confirmation email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Password Reset Successful - Terp Notes",
            html: `
                <h2>Password Reset Successful</h2>
                <p>Hello ${user.firstname},</p>
                <p>Your Terp Notes password has been successfully reset. You can now login with your new password.</p>
                <p><strong style="color: #DC2626;">If you didn't make this change, please contact support immediately at ${process.env.EMAIL_USER}.</strong></p>
                <hr style="margin: 2rem 0; border: none; border-top: 1px solid #E5E7EB;">
                <p style="color: #6B7280; font-size: 0.875rem;">
                    <strong>Terp Notes</strong> - Built for Terps, by Terps<br>
                    <em>Not affiliated with, endorsed by, or officially connected to the University of Maryland.</em>
                </p>
            `
        };
        transporter.sendMail(mailOptions, (err) => {
            if (err) console.error("Error sending email:", err);
        });

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
    } finally {
        await client.close();
    }
});

// Email verification route
app.get('/verify/:token', async (req, res) => {
    const token = req.params.token;

    try {
        await client.connect();

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
    } finally {
        await client.close();
    }
});

// Resend verification email
app.post('/resend-verification', async (req, res) => {
    try {
        await client.connect();

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

        console.log(`📧 Resending verification email to ${req.body.email}`);
        console.log(`🔗 Verification link: ${verificationLink}`);

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.body.email,
            subject: "Verify Your Terp Notes Account",
            html: `
                <h2>Verify Your Email, ${user.firstname}! 🐢</h2>
                <p>Click the button below to verify your email address:</p>
                <p><a href="${verificationLink}" style="background: #E03A3C; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">Verify Email Address</a></p>
                <p>Or copy this link: ${verificationLink}</p>
                <hr style="margin: 2rem 0; border: none; border-top: 1px solid #E5E7EB;">
                <p style="color: #6B7280; font-size: 0.875rem;">
                    <strong>Terp Notes</strong> - Built for Terps, by Terps<br>
                    <em>Not affiliated with, endorsed by, or officially connected to the University of Maryland.</em>
                </p>
            `
        };
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error("❌ Error resending verification email:", err);
                console.error("📧 Email config - User:", process.env.EMAIL_USER ? "Set" : "Missing");
            } else {
                console.log("✅ Resend verification email sent successfully:", info?.messageId);
            }
        });

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
    } finally {
        await client.close();
    }
});

app.get('/dashboard', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        await client.connect();

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
    } finally {
        await client.close();
    }
});

app.get('/profile', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        await client.connect();
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
    } finally {
        await client.close();
    }
});

app.post('/update-profile', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        await client.connect();

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

        // Send confirmation email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Profile Updated - Terp Notes",
            html: `
                <h2>Profile Updated Successfully</h2>
                <p>Hi ${firstname},</p>
                <p>Your Terp Notes profile has been successfully updated.</p>
                <p>If you didn't make this change, please contact support immediately.</p>
                <hr style="margin: 2rem 0; border: none; border-top: 1px solid #E5E7EB;">
                <p style="color: #6B7280; font-size: 0.875rem;">
                    <strong>Terp Notes</strong> - Built for Terps, by Terps<br>
                    <em>Not affiliated with, endorsed by, or officially connected to the University of Maryland.</em>
                </p>
            `
        };
        transporter.sendMail(mailOptions, (err) => {
            if (err) console.error("Error sending email:", err);
        });

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
    } finally {
        await client.close();
    }
});

app.post('/change-password', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        await client.connect();

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

        // Send confirmation email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Password Changed - Terp Notes",
            html: `
                <h2>Password Changed Successfully</h2>
                <p>Hi ${user.firstname},</p>
                <p>Your Terp Notes password has been successfully changed.</p>
                <p><strong style="color: #DC2626;">If you didn't make this change, please contact support immediately at ${process.env.EMAIL_USER}.</strong></p>
                <hr style="margin: 2rem 0; border: none; border-top: 1px solid #E5E7EB;">
                <p style="color: #6B7280; font-size: 0.875rem;">
                    <strong>Terp Notes</strong> - Built for Terps, by Terps<br>
                    <em>Not affiliated with, endorsed by, or officially connected to the University of Maryland.</em>
                </p>
            `
        };
        transporter.sendMail(mailOptions, (err) => {
            if (err) console.error("Error sending email:", err);
        });

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
    } finally {
        await client.close();
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

app.get("/delete/:filename", async (req, res) => {
    if (!req.session.user) return res.redirect("/login");

    const filename = decodeURIComponent(req.params.filename);

    try {
        await client.connect();

        // Check if user owns the file or is admin
        const fileDoc = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({ filename });

        if (!fileDoc) {
            return res.status(404).send("File not found.");
        }

        if (fileDoc.uploadedBy !== req.session.user.userid && req.session.user.role !== 'admin') {
            return res.status(403).send("You don't have permission to delete this file.");
        }

        // Check if this file is deduplicated (used by other uploads)
        const fileHash = fileDoc.fileHash;
        const duplicateFiles = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .countDocuments({ fileHash: fileHash });

        // Delete from S3 only if this is the last instance of this file
        if (duplicateFiles === 1) {
            await s3.deleteObject({ Bucket: AWS_BUCKET, Key: filename }).promise();
            console.log(`🗑️ Deleted file from S3: ${filename}`);
        } else {
            console.log(`♻️ File is deduplicated (${duplicateFiles} instances), keeping S3 file`);
        }

        // Delete metadata
        await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .deleteOne({ filename });

        // Delete all reports for this specific file (not affecting other instances if deduplicated)
        const deletedReports = await client
            .db(fileCollection.db)
            .collection('reports')
            .deleteMany({ filename: filename });

        if (deletedReports.deletedCount > 0) {
            console.log(`📋 Dismissed ${deletedReports.deletedCount} report(s) for deleted file`);
        }

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.session.user.email,
            subject: "File Deleted - Terp Notes",
            html: `
                <h2>File Deleted</h2>
                <p>Hi ${req.session.user.firstname},</p>
                <p>The file <strong>'${sanitizeForHeader(filename)}'</strong> has been deleted from your account.</p>
                <p>If you didn't perform this action, please contact support immediately.</p>
                <hr style="margin: 2rem 0; border: none; border-top: 1px solid #E5E7EB;">
                <p style="color: #6B7280; font-size: 0.875rem;">
                    <strong>Terp Notes</strong> - Built for Terps, by Terps<br>
                    <em>Not affiliated with, endorsed by, or officially connected to the University of Maryland.</em>
                </p>
            `
        };
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) console.error("Error sending deletion email:", err);
        });

        res.redirect("/dashboard");
    } catch (err) {
        console.error("Delete failed:", err);
        res.status(500).send("Error deleting file.");
    } finally {
        await client.close();
    }
});

app.get("/download/:filename", async (req, res) => {
    if (!req.session.user) return res.redirect("/login");

    const filename = decodeURIComponent(req.params.filename);
    const showWarning = req.query.warn;
    const params = { Bucket: AWS_BUCKET, Key: filename };

    try {
        await client.connect();
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
    } finally {
        await client.close();
    }
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

        // Normalize email to prevent duplicates (@umd.edu and @terpmail.umd.edu are the same)
        // Extract username part and always use @terpmail.umd.edu for storage
        const emailUsername = email.split('@')[0];
        const normalizedEmail = `${emailUsername}@terpmail.umd.edu`;

        // Trim and normalize user inputs
        const userid = req.body.userid.trim();
        const firstname = req.body.first_name.trim();
        const lastname = req.body.last_name.trim();

        // Check for existing email/username (check both formats)
        await client.connect();
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
            if (result.email === email) {
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
            createdAt: new Date()
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

        console.log(`📧 Sending verification email to ${email}`);
        console.log(`🔗 Verification link: ${verificationLink}`);
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify Your Terp Notes Account",
            html: `
                <h2>Welcome to Terp Notes, ${firstname}! 🐢</h2>
                <p>Thank you for registering. Please verify your email address to activate your account.</p>
                <p><a href="${verificationLink}" style="background: #E03A3C; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">Verify Email Address</a></p>
                <p>Or copy this link: ${verificationLink}</p>
                <p>This link will expire in 24 hours.</p>
                <p><small>If you didn't create this account, please ignore this email.</small></p>
                <hr style="margin: 2rem 0; border: none; border-top: 1px solid #E5E7EB;">
                <p style="color: #6B7280; font-size: 0.875rem;">
                    <strong>Terp Notes</strong> - Built for Terps, by Terps<br>
                    <em>Not affiliated with, endorsed by, or officially connected to the University of Maryland.</em>
                </p>
            `
        };
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error("❌ Error sending verification email:", err);
                console.error("📧 Email config - User:", process.env.EMAIL_USER ? "Set" : "Missing");
            } else {
                console.log("✅ Verification email sent successfully:", info?.messageId);
            }
        });

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
    } finally {
        await client.close();
    }
});

app.post('/loginSubmit', loginLimiter, async function (req, res) {
    try {
        await client.connect();
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

        req.session.user = userData;
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
    } finally {
        await client.close();
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
        await client.connect();

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
                    console.log(`♻️ Deduplicated: ${file.originalname} (reusing existing file)`);
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
                    virusScanDetails: existingFile ? existingFile.virusScanDetails : null
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

        // Send confirmation email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.session.user.email,
            subject: "Upload Successful - Terp Notes",
            html: `
                <h2>Upload Successful! 🎉</h2>
                <p>Hello ${req.session.user.firstname},</p>
                <p>You successfully uploaded <strong>${uploadedFiles.length} file(s)</strong> to <strong>${classCode}</strong>.</p>
                <p>Thanks for contributing to the Terp Notes community!</p>
                <hr style="margin: 2rem 0; border: none; border-top: 1px solid #E5E7EB;">
                <p style="color: #6B7280; font-size: 0.875rem;">
                    <strong>Terp Notes</strong> - Built for Terps, by Terps<br>
                    <em>Not affiliated with, endorsed by, or officially connected to the University of Maryland.</em>
                </p>
            `
        };
        transporter.sendMail(mailOptions, (err) => {
            if (err) console.error("Error sending email:", err);
        });

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
    } finally {
        await client.close();
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
        await client.connect();
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

        res.render('admin', {
            title: "Admin Dashboard",
            user: req.session.user,
            users: users,
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
    } finally {
        await client.close();
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

        await client.connect();

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
                    console.log(`🗑️ Admin deleted file from S3: ${report.filename}`);
                } else {
                    console.log(`♻️ File is deduplicated (${duplicateFiles} instances), keeping S3 file`);
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
                    console.log(`📋 Dismissed ${deletedReports.deletedCount - 1} additional report(s) for deleted file`);
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
    } finally {
        await client.close();
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

        await client.connect();

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
    } finally {
        await client.close();
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

        await client.connect();

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
    } finally {
        await client.close();
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

        await client.connect();

        await client
            .db(fileCollection.db)
            .collection('announcements')
            .deleteOne({ _id: new ObjectId(announcementId) });

        res.json({ success: true, message: 'Announcement deleted successfully' });
    } catch (error) {
        console.error('Error deleting announcement:', error);
        res.status(500).json({ error: 'Failed to delete announcement' });
    } finally {
        await client.close();
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

        await client.connect();

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
    } finally {
        await client.close();
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

        await client.connect();

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
    } finally {
        await client.close();
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
    } finally {
        await client.close();
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
        await client.connect();

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
                const s3Data = await s3.getObject({
                    Bucket: AWS_BUCKET,
                    Key: file.filename
                }).promise();

                // Don't await - let it run in background
                scanFileWithVirusTotal(file._id, s3Data.Body, file.originalName).catch(err => {
                    console.error('Cron scan error:', err);
                });
            } catch (s3Error) {
                console.error('Error fetching file for scan:', s3Error);
            }
        }

        res.json({
            message: 'Scan jobs triggered',
            scanned: pendingFiles.length
        });
    } catch (error) {
        console.error('Cron error:', error);
        res.status(500).json({ error: 'Cron job failed' });
    } finally {
        await client.close();
    }
});

// Export the app for testing
module.exports = app;

// Only start the server if this file is run directly
if (require.main === module) {
    try {
        app.listen(portNumber, () => {
            console.log(`🐢 Terp Notes Server running on port ${portNumber}`);
            console.log(`📚 Ready to share notes!`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}
