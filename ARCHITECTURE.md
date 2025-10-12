# 🏗️ Terp Notes Architecture

## Overview

Terp Notes is a production-ready class note-sharing platform built for University of Maryland students. This document outlines the technical architecture, design decisions, and system components.

---

## 🎯 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client (Browser)                         │
│         EJS Templates + Vanilla JS + CSS                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Homepage │  │Dashboard │  │  Admin   │  │ Profile  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↓ HTTPS
┌─────────────────────────────────────────────────────────────┐
│                   Express.js Server                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Auth Middleware│ │Rate Limiters│  │  Sessions    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Auth Routes  │  │ File Routes  │  │ Admin Routes │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
           ↓                  ↓                  ↓
    ┌──────────┐      ┌──────────┐      ┌──────────┐
    │ MongoDB  │      │  AWS S3  │      │VirusTotal│
    │  Atlas   │      │  Bucket  │      │   API    │
    └──────────┘      └──────────┘      └──────────┘
```

---

## 📊 **Database Schema**

### **Users Collection**

```javascript
{
  _id: ObjectId,
  userid: String,          // Username (permanent, unique)
  firstname: String,
  lastname: String,
  email: String,           // Normalized to @terpmail.umd.edu
  password: String,        // bcrypt hashed
  role: String,            // "admin" | "contributor" | "viewer"
  isVerified: Boolean,     // Email verification status
  verificationToken: String,
  resetToken: String,
  resetTokenExpiry: Date,
  createdAt: Date,
  isProtected: Boolean     // Prevents accidental deletion
}

// Indexes:
{ userid: 1 }, { unique: true }
{ email: 1 }, { unique: true }
{ role: 1 }
{ isVerified: 1, createdAt: 1 }  // For cleanup queries
```

### **Files Collection**

```javascript
{
  _id: ObjectId,
  filename: String,        // S3 key (timestamp_hash_originalname)
  originalName: String,
  s3Url: String,
  mimetype: String,
  size: Number,
  uploadDate: Date,
  uploadedBy: String,      // User ID
  classCode: String,       // e.g., "CMSC330"
  major: String,           // Extracted from classCode (e.g., "CMSC")
  semester: String,        // "Fall" | "Spring" | "Summer" | "Winter"
  year: String,            // e.g., "2025"
  professor: String,
  category: String,        // "exam" | "lecture notes" | "homework" | etc.
  description: String,     // Required
  fileHash: String,        // SHA-256 for deduplication
  virusScanStatus: String, // "pending" | "clean" | "infected" | "error"
  downloadCount: Number,   // Track popularity
  isNew: Boolean          // Flag for recently uploaded files
}

// Indexes:
{ classCode: 1 }
{ major: 1 }
{ uploadedBy: 1 }
{ fileHash: 1 }  // For deduplication
{ uploadDate: -1 }  // For sorting
{ virusScanStatus: 1 }  // For cron queries
{ category: 1 }  // For filtering
{ isNew: 1, uploadDate: -1 }  // For "new" badge logic
```

### **Reports Collection**

```javascript
{
  _id: ObjectId,
  filename: String,
  originalName: String,
  reportedBy: String,
  fileUploader: String,
  classCode: String,
  reason: String,
  details: String,
  reportedAt: Date,
  status: String  // "pending" | "resolved"
}

// Indexes:
{ status: 1, reportedAt: -1 }
{ filename: 1 }  // For cascading deletes
```

### **Announcements Collection**

```javascript
{
  _id: ObjectId,
  message: String,
  type: String,       // "info" | "warning" | "success"
  createdBy: String,
  createdAt: Date,
  isActive: Boolean
}

// Indexes:
{ isActive: 1, createdAt: -1 }
```

---

## 🔐 **Authentication Flow**

```
1. User visits /register
2. Enters: name, username, email, password
3. System validates:
   ✓ UMD email domain (@umd.edu or @terpmail.umd.edu)
   ✓ Email not already registered (checks both formats)
   ✓ Username not taken
   ✓ Passwords match
   ✓ Terms & Privacy accepted
4. Password hashed with bcrypt (10 rounds)
5. Verification token generated (crypto.randomBytes)
6. Email sent with verification link
7. User created in DB (isVerified: false)
8. User clicks email link → /verify/:token
9. Token validated → isVerified: true
10. User can now login
```

---

## 📤 **File Upload Flow**

```
1. User drags/selects files (up to 50, 100MB each)
2. Client-side validation (file count, required fields, category selection)
3. Form submitted to /upload (multipart/form-data)
4. Server: Multer processes files in memory
5. For each file:
   a. Calculate SHA-256 hash
   b. Check if hash exists in DB (deduplication)
   c. If new:
      - Upload to S3 (unique filename)
      - Save metadata to MongoDB (including category)
      - Mark virusScanStatus: "pending"
      - Set isNew: true
      - Trigger background virus scan
   d. If duplicate:
      - Reuse existing S3 file
      - Save new metadata record (different uploader)
6. Success page displayed
7. Background: VirusTotal scans file
8. Scan complete → Update virusScanStatus
9. If infected → Delete from S3 and MongoDB
```

---

## 🦠 **Virus Scanning Architecture**

### **Local Development:**
```
Upload → Scan starts immediately → 30-60s → Status updates
```

### **Vercel Production (Serverless):**
```
1. Upload (0:00) → File saved, marked "pending" → Response sent
2. Cron runs (0:05) → Picks up pending files
3. Cron triggers scans (max 5 per run)
4. Scan completes (0:06) → Status → "clean" or "infected"
5. User refreshes (0:07) → Sees status badge
```

**VirusTotal Integration:**
- Upload file to VT API
- Poll for scan results (every 15s, max 5 attempts)
- Update MongoDB with results
- Auto-delete if infected
- Free tier: 4 requests/min, 500/day

---

## 🔍 **Client-Side Filtering & UI Architecture**

### **Why Client-Side?**

**Traditional (Server-Side):**
```
User changes filter → AJAX request → DB query → Wait → Render
Time: ~200-500ms per filter change
```

**Our Approach (Client-Side):**
```
Page load → Fetch all metadata once → Store in JavaScript
User changes filter → Filter array in-browser → Instant update
Time: ~5-10ms per filter change
```

**Trade-offs:**
- ✅ Instant search (no loading)
- ✅ No server load
- ✅ Works offline
- ❌ Higher initial load (~50KB for 1000 files)
- ❌ Not ideal for 100K+ files

**Decision:** For a university note-sharing platform, we'll have hundreds to thousands of files, not hundreds of thousands. Client-side is the right choice.

### **View System Architecture**

**Three View Modes:**
1. **Grid View** - Card-based layout with icons and metadata
2. **List View** - Compact table format with inline actions
3. **Grouped View** - Hierarchical organization by semester/major/class

**Dynamic Filtering:**
- Real-time filter updates across all views
- Consistent filtering logic regardless of view mode
- Preserved filter state when switching views

---

## 🎨 **Design System & Icon Architecture**

### **Professional Icon System**

**Icon Categories:**
- **File Types:** PDF, DOC, ZIP, IMAGE, AUDIO, CODE, etc.
- **Actions:** Download, Delete, Upload, Search, Filter
- **Status:** New, Security, Virus Scan, Protected
- **Navigation:** Home, Dashboard, Admin, Profile
- **Categories:** Exam, Lecture Notes, Homework, Study Guide, etc.

**Technical Implementation:**
- Custom SVG/PNG icons with transparent backgrounds
- Consistent sizing (16px, 24px, 40px, 80px variants)
- Optimized file sizes for web performance
- Semantic naming convention (`new-badge.png`, `security-shield-check.png`)

### **UMD-Themed Color Scheme**

**Primary Colors:**
```css
--umd-red: #E21833;        /* Primary actions, headers */
--umd-gold: #FFD520;       /* Accent colors, highlights */
--umd-black: #000000;      /* Text, contrast */
--umd-white: #FFFFFF;      /* Backgrounds, cards */
```

**Functional Colors:**
```css
--success-green: #10B981;  /* Download buttons, success states */
--danger-red: #DC2626;     /* Delete buttons, warnings */
--info-blue: #3B82F6;      /* Info buttons, links */
--warning-yellow: #F59E0B; /* Warning states */
```

**Color-Coded Elements:**
- **Download Buttons:** Green (positive action)
- **Delete Buttons:** Red (destructive action)
- **Update Buttons:** Blue (safe action)
- **Folder Backgrounds:** UMD-themed gradients
- **Announcement Types:** Dynamic button colors

### **Component Architecture**

**Button System:**
```css
.button.primary    /* Blue - safe actions */
.button.danger     /* Red - destructive actions */
.button.download   /* Green - positive actions */
.button.secondary  /* Gray - secondary actions */
.button.info       /* Blue - information */
.button.warning    /* Yellow - warnings */
.button.success    /* Green - success states */
```

**Icon Integration:**
- Inline SVG/IMG tags with consistent sizing
- Alt text for accessibility
- Hover states and transitions
- Responsive scaling

---

## 🔒 **Security Architecture**

### **Defense Layers:**

1. **Email Verification**
   - Only verified @umd.edu/@terpmail.umd.edu emails
   - Token-based verification (crypto-secure)

2. **File Whitelisting**
   - Strict MIME type checking
   - Extension validation
   - Only academic file types

3. **Virus Scanning**
   - VirusTotal (70+ engines)
   - Background scanning
   - Auto-deletion of threats

4. **Rate Limiting**
   - Login: 10 attempts/15 min
   - Register: 10 attempts/hour
   - Upload: 20/hour
   - API: 100/15 min

5. **Role-Based Access**
   - Admin: Full access
   - Contributor: Upload/download/delete own
   - Viewer: Download only

6. **File Reporting**
   - Community moderation
   - Admin review dashboard

7. **Security Headers** (Helmet)
   - Content Security Policy
   - XSS Protection
   - HSTS

---

## 📈 **Performance Optimizations**

### **1. Database Indexing**

All critical fields indexed:
- Users: `userid`, `email`, `role`, `isVerified + createdAt`
- Files: `classCode`, `major`, `fileHash`, `uploadDate`, `virusScanStatus`, `category`, `isNew + uploadDate`
- Reports: `status + reportedAt`, `filename`
- Announcements: `isActive + createdAt`

**Impact:** Queries are O(log n) instead of O(n)

### **2. File Deduplication**

```javascript
// Hash file before upload
const fileHash = crypto.createHash('sha256')
  .update(file.buffer)
  .digest('hex');

// Check if exists
const existing = await db.files.findOne({ fileHash });

if (existing) {
  // Reuse S3 file, just save metadata
} else {
  // Upload new file
}
```

**Savings:** If 100 students upload same PDF, only 1 copy in S3!

### **3. Client-Side Filtering**

Load metadata once, filter in browser:
```javascript
const allFilesData = <%= JSON.stringify(files) %>;

function applyFilters() {
  const filtered = allFilesData.filter(file =>
    file.major === selectedMajor &&
    file.classCode === selectedClass
  );
  renderFiles(filtered);
}
```

**Speed:** ~5ms vs. ~200ms server query

### **4. Icon Optimization**

- SVG icons for scalability
- PNG fallbacks with transparency
- Optimized file sizes
- Consistent sizing system

### **5. Background Tasks**

- Virus scanning: Non-blocking
- Email sending: Async
- Cleanup tasks: Scheduled
- Database operations: Connection pooling

---

## 🌐 **Vercel Deployment Architecture**

### **Serverless Functions:**
Every route becomes a serverless function:
```
/login        → Function instance
/dashboard    → Function instance
/upload       → Function instance
/api/cron/... → Scheduled function
```

### **Cron Jobs:**
```javascript
// vercel.json
{
  "crons": [
    {
      "path": "/api/cron/scan-pending-files",
      "schedule": "*/5 * * * *"  // Every 5 minutes
    }
  ]
}
```

### **Environment:**
- Cold start: ~200-500ms (first request)
- Warm: ~50-100ms (subsequent requests)
- Timeout: 10s (free) / 60s (pro)

---

## 📁 **File Structure**

```
terp-notes/
├── server.js                 # Main application (3,270 lines)
├── package.json              # Dependencies
├── vercel.json              # Vercel config + cron
├── views/
│   ├── partials/
│   │   └── footer.ejs       # Reusable footer
│   ├── index.ejs            # Homepage with professional icons
│   ├── dashboard.ejs        # Main dashboard (3,907 lines)
│   ├── admin.ejs            # Admin panel with dynamic features
│   ├── profile.ejs          # User profile
│   ├── login.ejs            # Login page
│   ├── register.ejs         # Registration
│   ├── privacy.ejs          # Privacy Policy
│   ├── terms.ejs            # Terms of Service
│   ├── contact.ejs          # Contact page
│   └── ...                  # Error, success, 404, etc.
├── styles/
│   └── main.css             # All styles with UMD theme
├── public/
│   ├── images/
│   │   └── icons/           # Professional icon system
│   │       ├── new-badge.png
│   │       ├── security-shield-check.png
│   │       ├── folder.png
│   │       ├── briefcase.png
│   │       └── ... (30+ icons)
│   ├── favicon.png
│   └── logo.png
├── emails/
│   └── templates.js         # Email templates
├── middleware/
│   └── sessionTimeout.js    # Session management
├── utils/
│   └── passwordValidator.js # Password validation
└── README.md                # Project overview
```

---

## 🔄 **Data Flow Examples**

### **Dashboard Filtering:**

```
1. Page loads → Server queries MongoDB for ALL files
2. Data passed to EJS: files = [{...}, {...}, ...]
3. EJS renders: <script>const allFilesData = <%- JSON %></script>
4. User changes "Major" dropdown:
   → handleMajorChange() fires
   → Updates class dropdown options
   → Filters allFilesData in-memory
   → Re-renders file cards with appropriate icons
   → Time: ~5ms (instant!)
```

### **File Deduplication:**

```
1. User uploads "Lecture1.pdf"
2. Server calculates SHA-256 hash
3. Query: db.files.findOne({ fileHash: hash })
4. If found:
   → Reuse existing.filename (S3 key)
   → Save new metadata (different classCode/uploader)
   → Skip S3 upload
5. If not found:
   → Upload to S3
   → Save metadata
   → Trigger virus scan
```

### **Icon System:**

```
1. User selects category "Exam"
2. Frontend displays 📝 emoji + "Exam" text
3. File cards show appropriate category icons
4. Filter tags show category-specific icons
5. Consistent visual language across all views
```

---

## 🛡️ **Security Measures**

### **Input Sanitization:**

```javascript
// Filename sanitization
function sanitizeFilename(filename) {
  return filename
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/\.+/g, '.')
    .trim();
}

// Header injection prevention
function sanitizeHeader(value) {
  return value.replace(/[\r\n]/g, '').trim();
}

// HTML escaping for user content
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
```

### **Password Security:**

```javascript
// Registration
const hashedPassword = await bcrypt.hash(password, 10);

// Login
const match = await bcrypt.compare(inputPassword, storedHash);
```

### **Session Management:**

```javascript
// JWT token
const token = jwt.sign({ userid }, SECRET_KEY, { expiresIn: '7d' });

// Express session
req.session.user = { userid, role, ... };
```

---

## 📊 **Monitoring & Analytics**

### **Vercel Analytics:**
- Page views, unique visitors
- Traffic sources, geographic data
- Real-time monitoring

### **Speed Insights:**
- LCP (Largest Contentful Paint)
- FID (First Input Delay)
- CLS (Cumulative Layout Shift)
- FCP, TTFB, INP

### **Application Logs:**
```
🛡️ VirusTotal integration enabled
🐢 Terp Notes Server running on port 3000
📊 Database indexes created successfully
🧹 Cleaned up X unverified account(s)
🔄 Retrying X stuck virus scan(s)
🎨 Professional icon system loaded
```

---

## 🎨 **Design System**

### **Colors:**
```css
--umd-red: #E21833;        /* Primary brand color */
--umd-gold: #FFD520;       /* Accent color */
--umd-black: #000000;      /* Text, contrast */
--success-green: #10B981;  /* Download, success */
--danger-red: #DC2626;     /* Delete, warnings */
--info-blue: #3B82F6;      /* Info, updates */
--warning-yellow: #F59E0B; /* Warnings */
```

### **Components:**
- Gradient backgrounds (white → light gray)
- Red-to-gold accent bars
- Card-based layouts with shadows
- Pill-shaped inputs/filters
- Professional icon integration
- UMD-themed folder colors
- Responsive grid systems

### **Typography:**
- System fonts for performance
- Consistent hierarchy
- Readable line heights
- Accessible color contrast

---

## 🔮 **Scalability Considerations**

### **Current Capacity:**
- **Users:** 10K+ (with indexes)
- **Files:** 100K+ (with client-side filtering up to ~5K, then switch to server-side)
- **Storage:** 5GB free (S3), then pay-as-you-go
- **Bandwidth:** 100GB/month free (Vercel)
- **Icons:** Optimized for web performance

### **When to Optimize:**
1. **10K files:** Consider server-side pagination
2. **1GB S3:** Monitor costs, implement file expiration
3. **Heavy traffic:** Upgrade Vercel plan or add caching
4. **Slow queries:** Add compound indexes
5. **Large icon library:** Implement icon sprite system

---

## 📝 **Key Technical Decisions**

### **1. EJS vs React/Next.js**
**Choice:** EJS

**Why:**
- No build step
- Faster development
- Server-side rendering (SEO-friendly)
- Simpler deployment
- Perfect for content-heavy pages
- Professional icon system works seamlessly

### **2. MongoDB vs PostgreSQL**
**Choice:** MongoDB

**Why:**
- Flexible schema (easy to add fields like category, isNew)
- JSON-native (works well with Node.js)
- Free tier (Atlas M0)
- Easy to scale
- Great for document storage

### **3. S3 vs Database Storage**
**Choice:** AWS S3

**Why:**
- Designed for file storage
- Pay only for what you use
- Unlimited scalability
- Better performance
- CDN integration possible

### **4. Serverless vs VPS**
**Choice:** Vercel Serverless

**Why:**
- Free tier (100GB bandwidth)
- Auto-scaling
- Zero maintenance
- Built-in analytics
- Easy deployment

### **5. Custom Icons vs Icon Library**
**Choice:** Custom Icon System

**Why:**
- Perfect brand consistency
- Optimized file sizes
- Transparent backgrounds
- UMD-themed styling
- No external dependencies

---

## 🔧 **Critical Functions**

### **1. File Deduplication:**
```javascript
const fileHash = crypto.createHash('sha256')
  .update(file.buffer)
  .digest('hex');
```

### **2. Email Normalization:**
```javascript
const emailUsername = email.split('@')[0];
const normalizedEmail = `${emailUsername}@terpmail.umd.edu`;
```

### **3. Virus Scanning:**
```javascript
async function scanFileWithVirusTotal(fileId, fileBuffer, filename) {
  // Upload to VT
  // Poll for results
  // Update MongoDB
  // Delete if infected
}
```

### **4. Icon Integration:**
```javascript
function getCategoryEmoji(category) {
  const categoryEmojis = {
    'exam': '📝',
    'lecture notes': '📚',
    'homework': '✏️',
    // ... more categories
  };
  return categoryEmojis[category.toLowerCase()] || '📎';
}
```

### **5. Dynamic Button Colors:**
```javascript
// Update announcement button color based on type
const createBtn = document.getElementById('createAnnouncementBtn');
createBtn.classList.remove('info', 'warning', 'success');
createBtn.classList.add(type); // 'info', 'warning', or 'success'
```

### **6. Background Cleanup:**
```javascript
// Delete unverified accounts older than 7 days
setInterval(cleanupUnverifiedAccounts, 24 * 60 * 60 * 1000);
```

---

## 🚀 **Production Readiness**

### ✅ **Implemented:**
- Email verification
- Virus scanning
- Rate limiting
- File reporting
- Admin moderation
- Analytics
- Legal pages
- Error handling
- Database indexes
- File deduplication
- Responsive design
- Professional icon system
- UMD-themed design
- Multiple view modes
- Category system
- Dynamic filtering
- Color-coded buttons
- File metadata tracking

### 🔄 **Future Enhancements:**
- File versioning
- Comments/ratings
- Advanced search (full-text)
- Study group features
- AI-powered summaries
- Gamification (points, leaderboards)
- Dark mode toggle
- Advanced icon animations
- File preview improvements

---

**Built with 💙 for the University of Maryland community**