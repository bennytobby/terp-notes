# 🐢 Terp Notes

> A collaborative class note-sharing platform built for University of Maryland students, by a UMD student.

**Independent platform** - Not affiliated with, endorsed by, or officially connected to the University of Maryland.

## 🎯 The Problem

As a UMD student, I saw a recurring issue: **students struggle to find quality study materials**. Notes get lost, study guides aren't shared, and valuable resources remain siloed in individual Google Drives. While file-sharing platforms exist, there's no centralized, class-specific repository designed for UMD's course structure.

**Terp Notes** solves this by creating a dedicated space where Terps can share and discover resources organized by UMD's class codes—making it effortless to find materials for CMSC330, MATH141, or any course.

---

## 🛠️ Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **Backend** | Node.js + Express | Fast, scalable, serverless-ready |
| **Database** | MongoDB | Flexible schema for metadata, fast queries |
| **Storage** | AWS S3 | Scalable file storage, pay-per-use |
| **Auth** | JWT + Sessions + bcrypt | Secure, stateless tokens + server sessions |
| **Frontend** | EJS + Vanilla JS | Simple, fast, no build step needed |
| **Security** | VirusTotal API | 70+ antivirus engines, background scanning |
| **Monitoring** | Vercel Analytics + Speed Insights | Real-time traffic & performance tracking |

---

## 🎨 Design Philosophy

### **Why These Architectural Decisions?**

#### **1. Class-Based Organization (Not File Types)**
Students think in courses: *"I need CMSC330 notes"* is more natural than *"I need PDFs."* The entire UI revolves around class codes as the primary navigation paradigm.

#### **2. Two-Level Filtering (Major → Class)**
With 100+ courses at UMD, filtering by department (CMSC, MATH, HIST) first reduces cognitive load. Users narrow down by major, then select their specific class.

#### **3. Client-Side Filtering (Not Server Queries)**
Load all file metadata once, filter in-browser. This provides **instant search** without database roundtrips or page reloads—crucial for good UX.

**Trade-off:** Higher initial load (all metadata) vs. instant subsequent searches. For hundreds of files, this is still faster than repeated server queries.

#### **4. File Deduplication via SHA-256**
Multiple users upload the same "Lecture1.pdf"? Store it once in S3, reference it multiple times in MongoDB. Saves storage costs and prevents redundancy.

**Implementation:** Hash file buffer on upload → Check if hash exists → Reuse S3 key or upload new.

#### **5. Role-Based Access (Admin/Contributor/Viewer)**
Instead of banning violators, admins can revoke upload privileges ("Viewer" mode). Users still benefit from the platform while the community is protected.

**Rationale:** Encourages rehabilitation over punishment; users can regain privileges.

#### **6. Background Virus Scanning (Not Blocking)**
Files upload immediately (fast UX), scan happens asynchronously in background (slow but thorough). Users see "⏳ Scanning..." → "✓ Virus Scanned" within 1-5 minutes.

**Vercel Optimization:** Cron job runs every 5 minutes to scan pending files (serverless functions timeout at 10s, scans take 30-60s).

#### **7. Email Normalization (@umd.edu ↔ @terpmail.umd.edu)**
Both domains route to the same inbox. System normalizes to `@terpmail.umd.edu` to prevent duplicate accounts for the same user.

#### **8. No Anonymous Uploads**
Every file is tied to a verified UMD email. Accountability prevents abuse and enables moderation.

---

## ✨ Current Features

### **Core Functionality**
- 📚 **Class-Based Organization** - Files organized by major (CMSC, MATH) → class code (CMSC330)
- 🔍 **Instant Search** - Filter by filename, uploader, description (client-side, no reloads)
- 📤 **Drag-and-Drop Upload** - Bulk uploads (up to 50 files, 100MB each)
- 🎈 **Floating Action Button** - Quick access to upload from anywhere on page
- ⚡ **Smart Filtering** - Major dropdown dynamically updates class list

### **User Management**
- 🔐 **JWT + Session Auth** - Stateless tokens + server-side session validation
- 📧 **Email Verification** - Mandatory UMD email verification (`@umd.edu` / `@terpmail.umd.edu`)
- 👤 **Profile Management** - Update name/email/password (username permanent for accountability)
- 🛡️ **Three Roles:**
  - **Admin** - User management, moderation, announcements
  - **Contributor** - Upload, download, delete own files
  - **Viewer** - View-only (for policy violations)

### **Security & Moderation**
- 🦠 **VirusTotal Integration** - Background scanning with 70+ antivirus engines
- 🚩 **File Reporting** - Users flag inappropriate content → admin review dashboard
- 🛑 **Rate Limiting** - Prevents abuse (login, register, upload, API endpoints)
- 📝 **Audit Logs** - Track uploads, deletions, role changes
- ⚠️ **Download Warnings** - Security alerts for compressed files

### **Admin Tools**
- 📊 **Statistics Dashboard** - User count, file count, storage usage
- ⚖️ **Moderation Panel** - Review reported files, delete/dismiss
- 👥 **User Management** - Change roles, delete accounts, set view-only mode
- 📢 **Announcements** - Platform-wide banners (info/warning/success)

### **Technical Excellence**
- 💾 **File Deduplication** - SHA-256 hashing prevents duplicate storage
- 🔒 **Secure File Types** - Whitelist: documents, images, code files, archives
- 🗄️ **Database Indexing** - Fast queries on class codes, majors, dates
- 📊 **Vercel Analytics** - Page views, traffic sources, Web Vitals
- 🚀 **Serverless-Ready** - Cron jobs for background tasks on Vercel

---

## 🔒 Security Approach

### **Defense in Depth**
1. **Email Verification** - Only verified UMD emails can access
2. **File Whitelisting** - Safe academic file types only
3. **Virus Scanning** - VirusTotal with auto-deletion of threats
4. **Rate Limiting** - DDoS protection on all critical endpoints
5. **User Reporting** - Community-driven moderation
6. **Role-Based Access** - Granular permissions (Admin/Contributor/Viewer)
7. **Audit Trail** - All actions logged with timestamps

### **Academic Integrity**
- Prohibits unauthorized exam/project sharing
- Clear acceptable use policy during registration
- Reports serious violations to UMD Office of Student Conduct
- Admins can revoke upload privileges instead of banning

---

## 🔮 Future Vision

### **Optional (Future):**
- **Comments/Ratings** - Users can comment on and rate files for quality feedback
- **Download Analytics** - Track which files are most helpful to students
- **File Versioning** - Upload and manage multiple versions of the same file
- **AI Summaries** - Auto-generate summaries of uploaded PDFs and study guides
- **Gamification/Leaderboards** - Points for uploads and downloads, class-based leaderboards

### **Phase 2: Multi-University Expansion**
Expand beyond UMD to other universities with school-specific domains and admin teams.

### **Phase 3: Advanced Features**
- Study groups with private sharing
- Real-time collaborative annotations
- Class-specific discussion forums
- Q&A bot trained on class materials
- Auto-generate practice quizzes from notes
- LaTeX OCR for handwritten math

### **Phase 4: Analytics & Insights**
- Usage insights per class/department
- Trend analysis (popular topics before exams)
- Gap detection (classes with few resources)
- Download history tracking

---

## 🚀 Deployment & Development

**For detailed setup instructions, environment variables, and deployment guide:**
📖 **See [DEPLOYMENT.md](DEPLOYMENT.md)**

**Quick Start:**
```bash
npm install
npm start  # Runs on localhost:3000
```

**Tech Requirements:** Node.js 14+, MongoDB, AWS S3, (optional) VirusTotal API key

**Production:** Vercel-ready with cron jobs for background virus scanning

---

## 🏗️ Architecture Highlights

**Key Technical Decisions:**

1. **Client-Side Filtering**
   - Load all metadata once → instant search
   - Reduces server load + database queries

2. **Serverless Virus Scanning**
   - Files upload immediately (10s function timeout)
   - Cron job scans every 5 minutes
   - Users see "Scanning..." → "Scanned" within 1-5 min

3. **File Deduplication**
   - SHA-256 hash before upload
   - Reuse existing S3 objects if hash matches
   - Multiple metadata records → one file

4. **Email Normalization**
   - `pmachre@umd.edu` = `pmachre@terpmail.umd.edu`
   - Prevents duplicate accounts for same user

5. **Database Indexing**
   - Indexes on: `classCode`, `major`, `uploadDate`, `fileHash`
   - Fast queries even with 10K+ files

**For full architecture details:** See `server.js` (2300+ lines of documented code)

---

## 🤝 Contributing

This is a community-driven project for UMD students. Contributions welcome:
- 🐛 Report bugs via GitHub Issues
- 💡 Suggest features (especially UMD-specific needs)
- 📣 Spread the word to fellow Terps!

**Follow UMD's academic integrity guidelines when contributing.**

---

## 📄 License

MIT License - Built for Terps, by Terps 🐢

---

**Built with 💙 for the University of Maryland community**

*Fear the Turtle!* 🐢
