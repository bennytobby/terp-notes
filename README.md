# 🐢 Terp Notes

> **A free, student-driven platform for sharing class notes, study guides, and academic resources at the University of Maryland.**

**🚀 Live at:** [terp-notes.vercel.app](https://terp-notes.vercel.app/)

---

## 💡 The Story

I graduated from UMD and remember the struggle: hunting for study materials before exams, relying on fragmented GroupMe chats, and watching resources get lost semester after semester. **Notes that could help hundreds of students were trapped in individual Google Drives.**

I built **Terp Notes** to solve this problem—a centralized, searchable repository where Terps help Terps succeed. Whether you need CMSC330 lecture notes, MATH141 practice problems, or HIST156 study guides, it's all here. **Free. Always.**

This platform is **built for students, by a student** (now alum), with zero profit motive. Just Terps helping Terps. 🐢

**Note:** Terp Notes is an independent platform—not affiliated with, endorsed by, or officially connected to the University of Maryland.

---

## ✨ Features

### 📚 **For Students**
- **Instant Search** - Find notes by class code, professor, or keyword (no page reloads)
- **Smart Filtering** - Filter by major, class, semester, year, and professor
- **My Files Toggle** - Quickly view and manage only your uploads
- **Drag & Drop Upload** - Bulk upload up to 50 files at once (up to 5GB each!)
- **Direct S3 Uploads** - Files upload directly to cloud storage (no size limits)
- **File Preview** - PDFs and images open inline; download warnings for archives
- **Virus Scanning** - Every file scanned by 70+ antivirus engines (VirusTotal)
- **Mobile Responsive** - Works seamlessly on phones, tablets, and desktops
- **Email Notifications** - Confirmations for uploads, deletions, and account changes

### 🔐 **Security & Safety**
- **UMD Email Required** - Only verified `@umd.edu` / `@terpmail.umd.edu` emails can join
- **File Type Whitelisting** - Only safe academic files (PDFs, docs, images, code, zips)
- **Real-time Virus Scanning** - VirusTotal integration with auto-deletion of threats
- **Download Warnings** - Alerts for compressed files with additional security tips
- **Rate Limiting** - Protection against spam and abuse
- **File Reporting** - Flag inappropriate content for admin review
- **Account Deduplication** - Prevents multiple accounts for the same student

### 👥 **Community Features**
- **Platform Announcements** - Stay updated on important news and updates
- **Uploader Attribution** - See who contributed each file
- **File Metadata** - Class, professor, semester, year, and descriptions
- **Duplicate Detection** - System prevents re-uploading the same file

### 🛡️ **For Admins**
- **Moderation Dashboard** - Review reported files with one-click actions
- **User Management** - Change roles, set view-only mode, or remove accounts
- **Usage Statistics** - Track total users, files, and storage
- **Announcement System** - Create color-coded banners (info/warning/success)
- **Role-Based Access Control** - Admin, Contributor, and Viewer roles

### ⚡ **Technical Excellence**
- **Client-Side Filtering** - Instant results without server roundtrips
- **File Deduplication** - SHA-256 hashing saves storage costs
- **Database Indexing** - Fast queries even with thousands of files
- **Session Persistence** - Stay logged in across pages with JWT + cookies
- **Vercel Analytics** - Real-time traffic monitoring and performance insights
- **Cron Jobs** - Automated background tasks (virus scanning, cleanup)
- **Serverless Architecture** - Scales automatically with demand
- **No File Size Limits** - Direct S3 uploads support files up to 5GB

---

## 🚀 Why Use Terp Notes?

### **For Students Searching for Notes:**
✅ **Find resources in seconds** - No more digging through GroupMe or emailing classmates
✅ **Filter by your specific class** - CMSC330, MATH141, HIST156, etc.
✅ **Safe & virus-scanned** - Every file checked by 70+ antivirus engines
✅ **Free forever** - No paywalls, no ads, no subscription fees

### **For Students Contributing Notes:**
✅ **Help fellow Terps succeed** - Your notes could help hundreds of students
✅ **Build your reputation** - Your username is credited on every upload
✅ **Easy to upload** - Drag & drop, bulk upload, auto-fill metadata
✅ **Secure & private** - UMD email required, virus scanning enabled

### **For the UMD Community:**
✅ **Centralized knowledge base** - No more lost resources
✅ **Semester-to-semester continuity** - Help future students succeed
✅ **Class-specific organization** - Designed around UMD's course structure
✅ **Student-run** - Built by Terps, for Terps, with no corporate interests

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Backend** | Node.js + Express | Serverless API & routing |
| **Database** | MongoDB Atlas | File metadata & user management |
| **Storage** | AWS S3 | Scalable file storage with direct uploads |
| **Auth** | JWT + Sessions + bcrypt | Secure authentication & password hashing |
| **Frontend** | EJS + Vanilla JS + CSS | Server-side rendering with no build step |
| **Security** | VirusTotal API | 70+ antivirus engines scan every file |
| **Email** | Nodemailer + Gmail | Verification & notifications |
| **Deployment** | Vercel | Serverless functions, cron jobs, analytics |
| **Monitoring** | Vercel Analytics & Speed Insights | Performance tracking |

---

## 📊 Current Stats

**Platform Capacity (Free Tier):**
- ✅ Supports **1 million+** function invocations/month
- ✅ Handles **100GB** bandwidth/month
- ✅ Unlimited file uploads (storage costs ~$0.023/GB on S3)
- ✅ **5GB** max file size (S3 direct upload limit)
- ✅ **1 cron job** for daily virus scanning

**Perfect for a student community!** 🎓

---

## 🎯 How It Works

### **1. Register with UMD Email**
Sign up with your `@umd.edu` or `@terpmail.umd.edu` email → Receive verification link → Activate account

### **2. Browse & Search**
Filter by major (CMSC, MATH, etc.) → Select class (CMSC330) → Search by professor, semester, or keywords

### **3. Upload & Share**
Drag & drop your notes → Add class info & description → Upload directly to S3 → Files are virus scanned automatically

### **4. Download & Study**
Click any file → Preview PDFs inline or download → Help others by uploading your own materials

---

## 🏗️ Architecture Highlights

### **Why These Design Decisions?**

**Class-Based Organization**
Students think in courses ("I need CMSC330 notes"), not file types. The entire platform is organized around UMD's class code structure.

**Client-Side Filtering**
Load file metadata once, filter in-browser. Instant search without server delays.

**Direct S3 Uploads**
Files upload directly to AWS S3, bypassing Vercel's 4.5MB limit. Supports files up to 5GB!

**Background Virus Scanning**
Files upload immediately (fast UX), then scan asynchronously. No waiting for security checks.

**File Deduplication**
Same file uploaded by multiple users? Stored once in S3, referenced multiple times in MongoDB. Saves storage costs.

**Email Normalization**
`@umd.edu` and `@terpmail.umd.edu` route to the same inbox, preventing duplicate accounts.

**Role-Based Moderation**
Instead of banning violators, revoke upload privileges ("Viewer" mode). Encourages rehabilitation over punishment.

---

## 🛡️ Security & Privacy

### **Data We Collect:**
- UMD email (for verification)
- Name & username (for attribution)
- Uploaded files (stored on AWS S3)
- File metadata (class, professor, semester, description)

### **Data We DON'T Collect:**
- ❌ Browsing history
- ❌ Personal conversations
- ❌ Credit card info (platform is 100% free)
- ❌ Third-party tracking (only Vercel Analytics for performance)

### **Security Measures:**
- ✅ All passwords hashed with bcrypt (10 rounds)
- ✅ JWT tokens for stateless auth (24hr expiration)
- ✅ HTTPS enforced (Vercel auto-provisioned SSL)
- ✅ Rate limiting on all endpoints (prevents brute force)
- ✅ Session cookies are httpOnly & secure
- ✅ File virus scanning with auto-deletion
- ✅ Download warnings for potentially risky file types

**Full details:** [Privacy Policy](https://terp-notes.vercel.app/privacy)

---

## 📱 Screenshots

**Dashboard:**
Instant search, multi-select filters, drag & drop upload, virus scan status

**Admin Panel:**
User management, file moderation, usage statistics, announcement system

**Mobile Responsive:**
Works perfectly on phones, tablets, and desktops

---

## 🎓 Academic Integrity

**Terp Notes supports academic success, not academic dishonesty.**

### **✅ Allowed:**
- Lecture notes and study guides
- Practice problems and solutions (non-graded)
- Textbook summaries and chapter reviews
- Professor-approved materials
- Past exam study guides (with permission)

### **❌ Prohibited:**
- Current exams or quizzes
- Graded homework/projects
- Copyrighted materials without permission
- Answer keys for ongoing assignments
- Any content that violates UMD's academic integrity policy

**Violations are taken seriously** and may be reported to the UMD Office of Student Conduct.

---

## 🚀 Deployment

**Live Production:** [terp-notes.vercel.app](https://terp-notes.vercel.app/)

**Hosting:** Vercel (Serverless functions, auto-scaling, free tier)
**Storage:** AWS S3 (Direct client uploads, no file size limits)
**Database:** MongoDB Atlas (Free tier supports 512MB storage)

**Deployment Requirements:**
- MongoDB connection string
- AWS S3 bucket with CORS configured
- Gmail app password for email notifications
- (Optional) VirusTotal API key for scanning

**Full deployment guide:** See [ARCHITECTURE.md](ARCHITECTURE.md)

---

## 🤝 Contributing

This platform is **community-driven**. Here's how you can help:

**For Students:**
- 📤 Upload quality study materials
- 🚩 Report inappropriate content
- 📣 Share Terp Notes with classmates

**For Developers:**
- 🐛 Report bugs via GitHub Issues
- 💡 Suggest features
- 🔧 Submit pull requests

**Follow UMD's academic integrity guidelines when contributing.**

---

## 📞 Contact & Support

**Need help?** Visit [Contact & Support](https://terp-notes.vercel.app/contact)

**Questions about:**
- 🔐 Account issues → [Contact Form](https://terp-notes.vercel.app/contact)
- 🐛 Bugs or errors → GitHub Issues
- 📋 Feature requests → GitHub Discussions
- 📧 Direct support → Via contact form (we respond within 24-48 hours)

---

## 📄 Legal

- **Privacy Policy:** [terp-notes.vercel.app/privacy](https://terp-notes.vercel.app/privacy)
- **Terms of Service:** [terp-notes.vercel.app/terms](https://terp-notes.vercel.app/terms)
- **License:** MIT (see LICENSE file)

**Disclaimer:** Terp Notes is an independent, student-run platform. We are not affiliated with, endorsed by, or officially connected to the University of Maryland or any educational institution.

---

## 👨‍💻 Built By

**Paramraj Singh Machre**
UMD Alum | Full-Stack Developer | Building tools to help students succeed

- 🌐 **Portfolio:** [devcorpwebsite.vercel.app](https://devcorpwebsite.vercel.app/)
- 💼 **LinkedIn:** [linkedin.com/in/pmachre](https://linkedin.com/in/pmachre)
- 💻 **GitHub:** [github.com/bennytobby](https://github.com/bennytobby)

*Built with 💙 for the Terp community*

---

## 🎉 Get Started

**Ready to access thousands of study materials?**

👉 **[Join Terp Notes Now](https://terp-notes.vercel.app/)** 👈

1. **Sign up** with your UMD email
2. **Verify** your account (check inbox/spam)
3. **Browse** thousands of notes, guides, and resources
4. **Upload** your own materials to help fellow Terps
5. **Succeed** together! 🐢

---

**Fear the Turtle!** 🐢

*Questions? Feature ideas? Reach out via the [contact form](https://terp-notes.vercel.app/contact).*
