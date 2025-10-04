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
const { MongoClient, ServerApiVersion } = require('mongodb');
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

/* Port Configuration */
const portNumber = process.env.PORT || 3000;
console.log(`🐢 Terp Notes Server starting on port ${portNumber}`);

/* Express Setup */
const express = require("express");
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const app = express();
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
    const publicRoutes = ['/', '/login', '/register', '/loginSubmit', '/registerSubmit'];
    if (publicRoutes.includes(req.path)) {
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

/* Upload */
const multer = require("multer");
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB limit
    }
});

/* ROUTES */

app.get('/', function (req, res) {
    res.render('index', { title: "Terp Notes - UMD Resource Sharing" });
});

app.get('/register', function (req, res) {
    res.render('register', { title: "Register - Terp Notes" });
});

app.get('/login', function (req, res) {
    res.render('login', { title: "Login - Terp Notes" });
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

        await s3.deleteObject({ Bucket: AWS_BUCKET, Key: filename }).promise();

        await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .deleteOne({ filename });

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
    const params = { Bucket: AWS_BUCKET, Key: filename };

    try {
        const data = await s3.getObject(params).promise();

        await client.connect();
        const fileDoc = await client
            .db(fileCollection.db)
            .collection(fileCollection.collection)
            .findOne({ filename: filename });

        let downloadFilename = filename;
        if (fileDoc && fileDoc.originalName) {
            downloadFilename = fileDoc.originalName;
        }

        const sanitizedFilename = sanitizeForHeader(downloadFilename);

        res.setHeader("Content-Disposition", `attachment; filename="${sanitizedFilename}"`);
        res.send(data.Body);
    } catch (err) {
        console.error("S3 download error:", err);
        res.status(500).send("File could not be downloaded.");
    } finally {
        await client.close();
    }
});

app.post('/registerSubmit', async function (req, res) {
    try {
        await client.connect();
        let conflictFilter = {
            $or: [
                { email: req.body.email },
                { userid: req.body.userid }
            ]
        };
        const result = await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .findOne(conflictFilter);

        if (result) {
            if (result.email === req.body.email) {
                return res.render('error', {
                    title: "Email Exists",
                    message: "This email is already registered.",
                    link: "/register",
                    linkText: "Back to Registration"
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

        if (req.body.password !== req.body.confirm_pass) {
            return res.render('error', {
                title: "Password Mismatch",
                message: "The passwords entered do not match.",
                link: "/register",
                linkText: "Try Again"
            });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = {
            firstname: req.body.first_name,
            lastname: req.body.last_name,
            userid: req.body.userid,
            email: req.body.email,
            pass: hashedPassword,
            role: 'contributor', // All new users are contributors
            isProtected: false,
            createdAt: new Date()
        };

        await client
            .db(userCollection.db)
            .collection(userCollection.collection)
            .insertOne(newUser);

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.body.email,
            subject: "Welcome to Terp Notes!",
            text: `Hello ${req.body.first_name},\n\nWelcome to Terp Notes! Start sharing and downloading class notes with your fellow Terps.\n\n- Terp Notes Team 🐢`
        };
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) console.error("Error sending welcome email:", err);
        });

        return res.render('success', {
            title: "Registration Complete",
            message: "Your Terp Notes account has been created!",
            link: "/login",
            linkText: "Login Now"
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

app.post('/loginSubmit', async function (req, res) {
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
app.post("/upload", upload.array("documents", 50), async (req, res) => {
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
                    professor: req.body.professor || ""
                };

                await client
                    .db(fileCollection.db)
                    .collection(fileCollection.collection)
                    .insertOne(fileMeta);

                uploadedFiles.push(file.originalname);
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

        res.render('admin', {
            title: "Admin Dashboard",
            user: req.session.user,
            users: users
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.render('error', {
            title: "Database Error",
            message: "Failed to load user data.",
            link: "/dashboard",
            linkText: "Back to Dashboard"
        });
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

// Error handling middleware for multer file size errors
app.use((error, req, res, next) => {
    if (error.code === 'LIMIT_FILE_SIZE') {
        return res.render('error', {
            title: "File Too Large",
            message: "File exceeds the 100MB limit. Please choose a smaller file.",
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
