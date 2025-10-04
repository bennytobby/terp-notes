# Terp Notes Architecture

## Overview

Terp Notes is a class note-sharing platform built for University of Maryland students, adapted from the EDMS (Electronic Document Management System) architecture with class-based organization instead of document categories.

## Key Differences from EDMS

| Feature | EDMS | Terp Notes |
|---------|------|------------|
| Organization | Categories (documents, images, etc.) | Class Codes (CMSC330, MATH141, etc.) |
| Upload | Single file upload | **Bulk upload (up to 50 files)** |
| File Management | Role-based delete | **Users can only delete their own files** |
| Admin Control | Role management | **Set users to "viewer" role for view-only access** |
| Purpose | General document management | **Class-specific note sharing** |

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Interface                        │
│          (EJS Templates + CSS + JavaScript)                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                     Express.js Server                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Auth Routes  │  │ File Routes  │  │ Admin Routes │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
         ↓                    ↓                    ↓
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   MongoDB       │  │    AWS S3       │  │   Nodemailer    │
│  (Metadata)     │  │  (File Storage) │  │ (Notifications) │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Tech Stack

### Backend
- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **MongoDB** - Database for user and file metadata
- **AWS S3** - Cloud storage for uploaded files
- **JWT + Express Sessions** - Authentication
- **bcrypt** - Password hashing
- **Multer** - File upload handling
- **Nodemailer** - Email notifications

### Frontend
- **EJS** - Template engine
- **Vanilla JavaScript** - Client-side functionality
- **CSS3** - Styling with custom variables

## Database Schema

### Users Collection

```javascript
{
  _id: ObjectId,
  userid: String,          // Unique username
  firstname: String,
  lastname: String,
  email: String,           // Unique
  pass: String,            // Hashed with bcrypt
  role: String,            // 'admin', 'contributor', 'viewer'
  isProtected: Boolean,    // System accounts (can't be modified)
  createdAt: Date
}
```

### Files Collection

```javascript
{
  _id: ObjectId,
  filename: String,        // S3 key (timestamp_originalname)
  originalName: String,    // Original file name
  s3Url: String,          // Full S3 URL
  mimetype: String,       // File MIME type
  size: Number,           // File size in bytes
  uploadDate: Date,
  uploadedBy: String,     // User ID
  classCode: String,      // **NEW: Class code (e.g., "CMSC330")**
  description: String     // Optional description
}
```

## User Roles

### Admin
- Full system access
- Can upload, download, and delete any files
- Can manage all users (change roles, delete users)
- Access to admin dashboard
- **Can set users to "viewer" role to restrict uploads**

### Contributor (Default)
- Can upload unlimited files in bulk
- Can download any files
- **Can only delete their own files**
- No admin access

### Viewer (View-Only Mode)
- **Can only download files**
- **Cannot upload files**
- No admin access
- Used for users who violate policies

## Key Features

### 1. Class-Based Organization
Files are organized by class codes (e.g., CMSC330, MATH141) instead of generic categories.

```javascript
// Upload includes classCode
const fileMeta = {
  // ... other fields
  classCode: "CMSC330",  // Required field
};
```

### 2. Bulk File Upload
Users can upload up to 50 files at once using the `upload.array()` middleware.

```javascript
app.post("/upload", upload.array("documents", 50), async (req, res) => {
  // Process multiple files
  for (const file of files) {
    // Upload to S3 and save metadata
  }
});
```

### 3. File Ownership
Users can only delete their own files (admins can delete any file).

```javascript
// Permission check before delete
if (req.session.user.role !== 'admin' &&
    fileDoc.uploadedBy !== req.session.user.userid) {
  // Deny deletion
}
```

### 4. View-Only Mode
Admins can set users to "viewer" role to restrict upload access.

```javascript
// Check before upload
if (req.session.user.role === 'viewer') {
  return res.render('error', {
    message: "You don't have permission to upload files."
  });
}
```

### 5. Admin Dashboard
Comprehensive user management interface:
- View all users with statistics
- Change user roles (admin/contributor/viewer)
- Delete user accounts and their files
- Search and filter users

## File Upload Flow

```
1. User selects multiple files in browser
       ↓
2. Multer processes files in memory (up to 100MB each)
       ↓
3. Files are validated (size, count)
       ↓
4. Each file is uploaded to AWS S3
       ↓
5. File metadata is saved to MongoDB
       ↓
6. Email notification sent to user
       ↓
7. Success page displayed
```

## Authentication Flow

```
1. User submits login form
       ↓
2. Server finds user in database
       ↓
3. Password verified with bcrypt
       ↓
4. JWT token created and stored in cookie
       ↓
5. User data stored in session
       ↓
6. Redirect to dashboard
```

## Security Features

1. **Password Hashing**: bcrypt with salt rounds
2. **JWT Tokens**: Secure session management
3. **Protected Accounts**: System accounts can't be modified
4. **Input Sanitization**: Filename and header sanitization
5. **Role-Based Access**: Middleware checks permissions
6. **Session Validation**: Every request validates session

## API Endpoints

### Public Routes
- `GET /` - Landing page
- `GET /login` - Login page
- `POST /loginSubmit` - Login handler
- `GET /register` - Registration page
- `POST /registerSubmit` - Registration handler

### Protected Routes
- `GET /dashboard` - Main dashboard with file list
- `POST /upload` - Bulk file upload (up to 50 files)
- `GET /download/:filename` - File download
- `GET /delete/:filename` - Delete file (own files only)
- `GET /logout` - Logout

### Admin Routes
- `GET /admin` - Admin dashboard
- `POST /api/update-user-role` - Update user role
- `POST /api/delete-user` - Delete user account

## Environment Variables

Required environment variables:

```env
# Database
MONGO_CONNECTION_STRING  # MongoDB connection string
MONGO_DB_NAME           # Database name
MONGO_FILECOLLECTION    # Files collection name
MONGO_USERCOLLECTION    # Users collection name

# AWS
AWS_ACCESS_KEY_ID       # AWS access key
AWS_SECRET_ACCESS_KEY   # AWS secret key
AWS_REGION             # S3 region
AWS_S3_BUCKET          # S3 bucket name

# Security
SECRET_KEY             # JWT and session secret

# Email (Optional)
EMAIL_USER             # Gmail address
EMAIL_PASS             # Gmail app password

# Server
PORT                   # Server port (default: 3000)
NODE_ENV              # Environment (development/production)
```

## Performance Considerations

1. **File Size Limit**: 100MB per file
2. **Concurrent Uploads**: Up to 50 files at once
3. **Database Indexing**:
   - Index on `userid` for faster user lookups
   - Index on `classCode` for faster class filtering
4. **Caching**: Static files served with Express static middleware
5. **Connection Pooling**: MongoDB client reuses connections

## Deployment

### Vercel Deployment
1. Configure `vercel.json` for Node.js serverless functions
2. Set all environment variables in Vercel dashboard
3. Deploy with `vercel --prod`

### Environment Setup
- Ensure MongoDB Atlas allows Vercel IP addresses
- Configure AWS S3 CORS for production domain
- Use strong SECRET_KEY in production

## Future Enhancements

1. **File Versioning**: Track multiple versions of same file
2. **Comments/Reviews**: Allow users to comment on files
3. **File Previews**: Preview PDFs and images in-browser
4. **Search Enhancement**: Full-text search on file contents
5. **Analytics**: Track popular classes and files
6. **Direct S3 Uploads**: Client-side uploads with signed URLs
7. **File Sharing Links**: Generate shareable links
8. **Notification System**: Real-time notifications for new uploads

## Maintenance

### Logs
- Application logs to console
- MongoDB connection status
- S3 upload/download status
- Email notification status

### Monitoring
- Check MongoDB connection health
- Monitor S3 bucket usage
- Track user registration trends
- Monitor file upload success rates

---

*Architecture designed for scalability and maintainability*

