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

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
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
    resave: true,
    saveUninitialized: true,
    rolling: true,
    name: 'terpnotes.sid',
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax'
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
    const publicRoutes = ['/', '/login', '/register', '/loginSubmit', '/registerSubmit', '/forgot-password', '/resend-verification'];
    const publicRoutesRegex = /^\/(verify|reset-password)\/.+/; // Match /verify/:token and /reset-password/:token

    if (publicRoutes.includes(req.path) || publicRoutesRegex.test(req.path)) {
        return next();
    }

    const sessionUser = req.session.user;
    const authToken = req.cookies ? req.cookies.authToken : null;
    const jwtUser = authToken ? verifyToken(authToken) : null;

    if (jwtUser && !sessionUser) {
        req.session.user = jwtUser;
    }

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

/* Password Hashing */
const bcrypt = require('bcrypt');

/* File Hashing for Deduplication */
const crypto = require('crypto');

// Function to create protected system accounts
async function createProtectedSystemAccounts() {
    try {
        await client.connect();

        const systemAccounts = [
            {
                firstname: 'System',
                lastname: 'Admin',
                userid: 'admin',
                email: 'admin@terpnotes.umd.edu',
                pass: await bcrypt.hash('admin', 10),
                role: 'admin',
                isProtected: true,
                isVerified: true,
                createdAt: new Date()
            },
            {
                firstname: 'Test',
                lastname: 'Terp',
                userid: 'terp',
                email: 'terp@terpnotes.umd.edu',
                pass: await bcrypt.hash('terp', 10),
                role: 'contributor',
                isProtected: true,
                isVerified: true,
                createdAt: new Date()
            },
            {
                firstname: 'View',
                lastname: 'Only',
                userid: 'viewer',
                email: 'viewer@terpnotes.umd.edu',
                pass: await bcrypt.hash('viewer', 10),
                role: 'viewer',
                isProtected: true,
                isVerified: true,
                createdAt: new Date()
            }
        ];

        for (const account of systemAccounts) {
            const existingUser = await client
                .db(userCollection.db)
                .collection(userCollection.collection)
                .findOne({ userid: account.userid });

            if (!existingUser) {
                await client
                    .db(userCollection.db)
                    .collection(userCollection.collection)
                    .insertOne(account);
                console.log(`✅ Created protected system account: ${account.userid}`);
            } else {
                if (!existingUser.isProtected) {
                    await client
                        .db(userCollection.db)
                        .collection(userCollection.collection)
                        .updateOne(
                            { userid: account.userid },
                            { $set: { isProtected: true } }
                        );
                    console.log(`🛡️ Updated existing account to protected: ${account.userid}`);
                }
            }
        }
    } catch (error) {
        console.error('Error creating protected system accounts:', error);
    } finally {
        await client.close();
    }
}

// Create protected system accounts on server startup
createProtectedSystemAccounts();

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
        const resetLink = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
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
                <p>- Terp Notes Team 🐢</p>
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
            subject: "Terp Notes Password Reset Successful",
            text: `Hello ${user.firstname},\n\nYour Terp Notes password has been successfully reset.\n\nIf you didn't make this change, please contact support immediately.\n\n- Terp Notes Team 🐢`
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
        const verificationLink = `${req.protocol}://${req.get('host')}/verify/${verificationToken}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.body.email,
            subject: "Verify Your Terp Notes Account",
            html: `
                <h2>Verify Your Email, ${user.firstname}! 🐢</h2>
                <p>Click the button below to verify your email address:</p>
                <p><a href="${verificationLink}" style="background: #E03A3C; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">Verify Email Address</a></p>
                <p>Or copy this link: ${verificationLink}</p>
                <p>- Terp Notes Team</p>
            `
        };
        transporter.sendMail(mailOptions, (err) => {
            if (err) console.error("Error sending verification email:", err);
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

        res.render('dashboard', {
            firstname: req.session.user.firstname,
            email: req.session.user.email,
            user: req.session.user,
            files: allFiles,
            majors: uniqueMajors,
            classCodes: uniqueClassCodes
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

        const { firstname, lastname, email } = req.body;

        // Check if email is being changed and if it already exists
        if (email !== req.session.user.email) {
            const existingUser = await client
                .db(userCollection.db)
                .collection(userCollection.collection)
                .findOne({ email: email });

            if (existingUser && existingUser.userid !== req.session.user.userid) {
                return res.render('error', {
                    title: "Email Already Exists",
                    message: "This email is already registered to another account.",
                    link: "/profile",
                    linkText: "Back to Profile"
                });
            }
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
            subject: "Terp Notes Profile Updated",
            text: `Hi ${firstname},\n\nYour profile has been successfully updated.\n\n- Terp Notes Team`
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
            subject: "Terp Notes Password Changed",
            text: `Hi ${user.firstname},\n\nYour password has been successfully changed.\n\nIf you didn't make this change, please contact support immediately.\n\n- Terp Notes Team`
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
            subject: "Terp Notes - File Deletion Notice",
            text: `Hi ${req.session.user.firstname},\n\nThe file '${sanitizeForHeader(filename)}' has been deleted from your account.\n\n- Terp Notes Team`
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

        // Check for existing email/username
        await client.connect();
        let conflictFilter = {
            $or: [
                { email: email },
                { userid: req.body.userid }
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
            if (result.userid === req.body.userid) {
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

        const newUser = {
            firstname: req.body.first_name,
            lastname: req.body.last_name,
            userid: req.body.userid,
            email: email,
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
        const verificationLink = `${req.protocol}://${req.get('host')}/verify/${verificationToken}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify Your Terp Notes Account",
            html: `
                <h2>Welcome to Terp Notes, ${req.body.first_name}! 🐢</h2>
                <p>Thank you for registering. Please verify your email address to activate your account.</p>
                <p><a href="${verificationLink}" style="background: #E03A3C; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">Verify Email Address</a></p>
                <p>Or copy this link: ${verificationLink}</p>
                <p>This link will expire in 24 hours.</p>
                <p><small>If you didn't create this account, please ignore this email.</small></p>
                <p>- Terp Notes Team</p>
            `
        };
        transporter.sendMail(mailOptions, (err) => {
            if (err) console.error("Error sending verification email:", err);
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
        let filter = { userid: req.body.userid };
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

        const { firstname, lastname, userid, email, role } = result;
        const userData = { firstname, lastname, userid, email, role };

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
            subject: "Terp Notes - Upload Confirmation",
            text: `Hello ${req.session.user.firstname},\n\nYou have successfully uploaded ${uploadedFiles.length} file(s) to ${classCode}.\n\n- Terp Notes Team 🐢`
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

        res.render('admin', {
            title: "Admin Dashboard",
            user: req.session.user,
            users: users,
            reports: reports
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
            console.log(`🐢 Terp Notes Server running on port ${portNumber}`);
            console.log(`📚 Ready to share notes!`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}
