# 🐢 Terp Notes

> A collaborative class note-sharing platform built for University of Maryland students, by a UMD student.

## 🎯 The Story

As a UMD student, I noticed a recurring problem: **students struggle to find quality study materials for their classes**. Notes get lost, study guides aren't shared, and valuable resources remain siloed. While platforms like Google Drive exist, there's no centralized, class-specific repository for UMD students.

**Terp Notes** solves this by creating a dedicated space where Terps can share lecture notes, study guides, and course materials organized by class code—making it effortless to find resources for CMSC330, MATH141, or any UMD course.

## ✨ Current Features

### Core Functionality
- **📚 Class-Based Organization** - Files organized by department (CMSC, MATH, HIST) and class code (CMSC330, MATH141)
- **📤 Drag-and-Drop Upload** - Intuitive upload interface supporting single or bulk file uploads (up to 50 files)
- **🔍 Smart Filtering** - Two-level filtering (Major → Class) with instant client-side search
- **⚡ Real-Time Search** - Filter by filename, uploader, class code, or description without page reloads
- **🎈 Floating Action Button** - Quick access to upload from anywhere on the page

### User Management
- **🔐 Secure Authentication** - JWT + session-based auth with bcrypt password hashing
- **👤 Profile Management** - Users can update names, emails, and passwords (username is permanent)
- **🛡️ Role-Based Access Control**:
  - **Admin** - Full system access, user management
  - **Contributor** - Upload, download, delete own files
  - **Viewer** - View-only mode for policy violations

### Admin Tools
- **📊 Admin Dashboard** - Manage users, change roles, view statistics
- **⚖️ Moderation** - Set violators to view-only mode or delete accounts
- **📋 Acceptable Use Policy** - Clear terms with academic integrity warnings

### Technical Excellence
- **☁️ AWS S3 Storage** - Scalable cloud storage for files up to 100MB each
- **💾 MongoDB** - Fast metadata queries with major/class indexing
- **📧 Email Verification** - UMD email verification required for account creation
- **🔒 Secure File Uploads** - Whitelisted file types for safety (documents, images, code, .zip only)
- **🎨 UMD-Themed UI** - Official red and gold colors with responsive design

## 🛠️ Tech Stack

**Backend:** Node.js, Express.js, MongoDB, AWS S3
**Frontend:** EJS, Vanilla JavaScript, CSS3
**Auth:** JWT, Express Sessions, bcrypt
**Storage:** AWS S3 (files), MongoDB (metadata)
**Deployment:** Vercel-ready with serverless support

## 🚀 Design Philosophy

### Why These Choices?

**Class-Based Organization**
Students think in terms of classes, not file types. "I need CMSC330 notes" is more natural than "I need documents."

**Two-Level Filtering (Major → Class)**
With hundreds of courses at UMD, filtering by department first (CMSC, MATH) makes finding specific classes faster.

**Client-Side Filtering**
Loading all files once and filtering in-browser provides instant results without database queries or page reloads—crucial for a smooth user experience.

**View-Only Mode for Violations**
Instead of immediate bans, admins can revoke upload privileges, allowing users to still benefit from the platform while protecting the community.

**No Anonymous Uploads**
Accountability prevents abuse. Every file is tied to a user, encouraging responsible sharing.

## 🔮 Future Scope

### Phase 1: Enhanced Security & Verification *(Completed! 🎉)*
- ✅ **Email Verification** - Require `@umd.edu` or `@terpmail.umd.edu` emails for registration
- ✅ **File Type Whitelisting** - Safe academic file types only
- ✅ **User Reporting System** - Flag inappropriate content for admin review
- ✅ **Rate Limiting** - Prevent abuse and DDoS attacks
- ✅ **Virus Scanning** - VirusTotal integration with background scanning
- 🔄 **Expanded File Types** - Add more formats (.rar, .7z, etc.) after testing scanning
- ⏳ **Two-Factor Authentication** - Optional 2FA for account security *(Future)*

### Phase 2: Multi-University Platform
- **School Selection** - Expand beyond UMD to other universities
- **University-Specific Domains** - `umd.terpnotes.com`, `umbc.terpnotes.com`, etc.
- **Cross-School Resources** - Share general study techniques across universities
- **Admin per School** - Decentralized moderation teams

### Phase 3: Gamification & Engagement
- **Contribution Tokens** - Earn points for uploading helpful resources
- **Leaderboard System** - Top contributors per class/semester
- **Achievement Badges** - Unlock badges for milestones (10 uploads, 100 downloads, etc.)
- **Reputation System** - Upvote/downvote files to surface the best content
- **Semester Challenges** - Competition between majors for most contributions

### Phase 4: AI-Powered Study Assistant
- **Smart Summaries** - AI generates summaries of uploaded PDFs
- **Q&A Bot** - Ask questions about class materials, get answers from uploaded notes
- **Concept Extraction** - Automatically tag files with key topics (Binary Trees, Recursion, etc.)
- **Study Recommendations** - "Students who studied CMSC330 also found these CMSC351 notes helpful"
- **Practice Quiz Generation** - Auto-generate quizzes from uploaded study guides
- **LaTeX OCR** - Convert handwritten math notes to searchable text

### Phase 5: Collaboration Features
- **Study Groups** - Create private groups for team-based sharing
- **Real-Time Annotations** - Collaborative note-taking on shared PDFs
- **Discussion Forums** - Class-specific discussion boards
- **Office Hours Scheduler** - Connect students for peer tutoring

### Phase 6: Advanced Analytics
- **Usage Insights** - See which classes have the most shared resources
- **Trend Analysis** - Identify popular topics before exams
- **Gap Detection** - Alert users to classes with few resources
- **Download History** - Track your study materials for review

## 🔒 Security & Safety

Terp Notes prioritizes user security and academic integrity:

### Current Security Measures
- ✅ **Email Verification** - Only verified `@umd.edu` or `@terpmail.umd.edu` addresses
- ✅ **File Type Whitelisting** - Only safe academic files (documents, images, code, .zip)
- ✅ **Virus Scanning** - VirusTotal integration with 70+ antivirus engines
  - Background scanning (files upload immediately, scan happens asynchronously)
  - Auto-deletion of infected files
  - Visual status badges (✓ Virus Scanned, ⏳ Scanning, ⚠️ Error)
- ✅ **Rate Limiting** - Protection against abuse and automated attacks
- ✅ **User Reporting** - Community-driven moderation with admin review
- ✅ **Role-Based Access** - Granular permission control (Admin/Contributor/Viewer)
- ✅ **Secure Authentication** - JWT + bcrypt password hashing
- ✅ **File Deduplication** - SHA-256 hashing prevents duplicate storage

### Coming Soon
- 🔄 **Expanded File Support** - More file types (.rar, .7z) once scanning is battle-tested
- 🔄 **Download Warnings** - Enhanced security alerts for compressed files
- 🔄 **Scan History Dashboard** - Admin view of all scan results and threats blocked

### Academic Integrity
- Prohibits unauthorized exam/project sharing
- Clear acceptable use policies with consequences
- Reports serious violations to UMD Office of Student Conduct
- Admin moderation dashboard for swift action

## 🚀 Getting Started

### Prerequisites
- Node.js (v14 or higher)
- MongoDB database
- AWS S3 bucket
- (Optional) VirusTotal API key for virus scanning

### Setup
1. Clone the repository
2. Copy `.env.example` to `.env` and fill in your credentials
3. Install dependencies: `npm install`
4. Start the server: `npm start`
5. Visit `http://localhost:3000`

### Default Accounts
- **Admin:** `admin` / `admin`
- **Contributor:** `terp` / `terp`
- **Viewer:** `viewer` / `viewer`
- Or create your own with a UMD email!

### VirusTotal Integration
To enable virus scanning:
1. Sign up for free at [virustotal.com](https://www.virustotal.com/)
2. Get your API key from [My API Key](https://www.virustotal.com/gui/my-apikey)
3. Add `VIRUSTOTAL_API_KEY=your_key` to `.env`
4. Free tier: 500 scans/day, 4 requests/minute

## 🏗️ Architecture

Built with scalability and maintainability in mind. See [ARCHITECTURE.md](ARCHITECTURE.md) for technical details on:
- Database schema design
- Authentication flow
- File upload architecture
- Client-side filtering implementation

## 🤝 Contributing

This project is built for the UMD community. If you'd like to contribute:
- Report bugs or suggest features via issues
- Follow UMD's academic integrity guidelines
- Help spread the word to fellow Terps!

## 📄 License

MIT License - Built for Terps, by Terps 🐢

---

**Built with 💙 for the University of Maryland community**
*Fear the Turtle!* 🐢
