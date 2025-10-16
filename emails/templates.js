/**
 * Email Templates for Terp Notes
 * All emails use the terp-notes.org domain via Resend
 */

// Base email wrapper with consistent styling
function emailWrapper(content) {
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; background-color: #F3F4F6;">
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 40px 20px;">
                <div style="background: white; border-radius: 12px; padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                    <div style="text-align: center; margin-bottom: 24px;">
                        <img src="https://terp-notes.org/logo.png" alt="Terp Notes Logo" style="width: 80px; height: 80px; margin: 0 auto;" />
                    </div>
                    ${content}
                </div>
                <div style="text-align: center; padding: 20px; color: #6B7280; font-size: 0.875rem;">
                    <p style="margin: 0;"><strong>Terp Notes</strong> - Built for Terps, by Terps</p>
                    <p style="margin: 4px 0 0 0;"><em>Not affiliated with, endorsed by, or officially connected to the University of Maryland.</em></p>
                </div>
            </div>
        </body>
        </html>
    `;
}

// Button component
function button(url, text) {
    return `<a href="${url}" style="display: inline-block; background: #E03A3C; color: white; padding: 12px 32px; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 16px 0;">${text}</a>`;
}

// Divider
function divider() {
    return `<hr style="margin: 24px 0; border: none; border-top: 1px solid #E5E7EB;">`;
}

/**
 * Verification Email (Registration)
 */
function verificationEmail(firstname, verificationLink) {
    const content = `
        <h2 style="color: #E03A3C; margin-top: 0;">Welcome to Terp Notes, ${firstname}!</h2>
        <p style="color: #374151; line-height: 1.6;">Thank you for registering. Please verify your email address to activate your account.</p>
        ${button(verificationLink, 'Verify Email Address')}
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 20px;">Or copy this link:<br><a href="${verificationLink}" style="color: #E03A3C; word-break: break-all;">${verificationLink}</a></p>
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 16px;">This link will expire in 24 hours.</p>
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 8px;"><em>If you didn't create this account, please ignore this email.</em></p>
    `;
    return emailWrapper(content);
}

/**
 * Resend Verification Email
 */
function resendVerificationEmail(firstname, verificationLink) {
    const content = `
        <h2 style="color: #E03A3C; margin-top: 0;">Verify Your Email, ${firstname}!</h2>
        <p style="color: #374151; line-height: 1.6;">Click the button below to verify your email address:</p>
        ${button(verificationLink, 'Verify Email Address')}
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 20px;">Or copy this link:<br><a href="${verificationLink}" style="color: #E03A3C; word-break: break-all;">${verificationLink}</a></p>
    `;
    return emailWrapper(content);
}

/**
 * Password Reset Request Email
 */
function passwordResetEmail(firstname, resetLink) {
    const content = `
        <h2 style="color: #E03A3C; margin-top: 0;">Password Reset Request</h2>
        <p style="color: #374151; line-height: 1.6;">Hello ${firstname},</p>
        <p style="color: #374151; line-height: 1.6;">We received a request to reset your Terp Notes password. Click the button below to create a new password:</p>
        ${button(resetLink, 'Reset Password')}
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 20px;">Or copy this link:<br><a href="${resetLink}" style="color: #E03A3C; word-break: break-all;">${resetLink}</a></p>
        <p style="color: #DC2626; font-size: 0.875rem; font-weight: 600; margin-top: 16px;">This link will expire in 1 hour.</p>
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 8px;"><em>If you didn't request this, please ignore this email. Your password will not be changed.</em></p>
    `;
    return emailWrapper(content);
}

/**
 * Password Reset Success Email
 */
function passwordResetSuccessEmail(firstname) {
    const content = `
        <h2 style="color: #10B981; margin-top: 0;">Password Reset Successful</h2>
        <p style="color: #374151; line-height: 1.6;">Hello ${firstname},</p>
        <p style="color: #374151; line-height: 1.6;">Your Terp Notes password has been successfully reset. You can now login with your new password.</p>
        ${divider()}
        <p style="color: #DC2626; font-size: 0.875rem; font-weight: 600;"><strong>Important:</strong> If you didn't make this change, please contact support immediately at <a href="mailto:noreply@terp-notes.org" style="color: #E03A3C;">noreply@terp-notes.org</a></p>
    `;
    return emailWrapper(content);
}

/**
 * Password Change Confirmation Email
 */
function passwordChangeEmail(firstname) {
    const content = `
        <h2 style="color: #10B981; margin-top: 0;">Password Changed Successfully</h2>
        <p style="color: #374151; line-height: 1.6;">Hi ${firstname},</p>
        <p style="color: #374151; line-height: 1.6;">Your Terp Notes password has been successfully changed.</p>
        ${divider()}
        <p style="color: #DC2626; font-size: 0.875rem; font-weight: 600;"><strong>Important:</strong> If you didn't make this change, please contact support immediately at <a href="mailto:noreply@terp-notes.org" style="color: #E03A3C;">noreply@terp-notes.org</a></p>
    `;
    return emailWrapper(content);
}

/**
 * Profile Update Confirmation Email
 */
function profileUpdateEmail(firstname) {
    const content = `
        <h2 style="color: #10B981; margin-top: 0;">Profile Updated Successfully</h2>
        <p style="color: #374151; line-height: 1.6;">Hi ${firstname},</p>
        <p style="color: #374151; line-height: 1.6;">Your Terp Notes profile has been successfully updated.</p>
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 16px;">If you didn't make this change, please contact support immediately.</p>
    `;
    return emailWrapper(content);
}

/**
 * Account Deletion Confirmation Email
 */
function accountDeletionEmail(firstname) {
    const content = `
        <h2 style="color: #DC2626; margin-top: 0;">Account Deleted Successfully</h2>
        <p style="color: #374151; line-height: 1.6;">Hi ${firstname},</p>
        <p style="color: #374151; line-height: 1.6;">Your Terp Notes account has been permanently deleted as requested.</p>
        <p style="color: #374151; line-height: 1.6;"><strong>The following data has been removed:</strong></p>
        <ul style="color: #374151; line-height: 1.8;">
            <li>Your profile and account information</li>
            <li>Your download history and statistics</li>
            <li>Your email preferences</li>
        </ul>
        <p style="color: #374151; line-height: 1.6;"><strong>Files you uploaded:</strong></p>
        <p style="color: #6B7280; line-height: 1.6;">Your uploaded files have been anonymized and will remain available to the community as "Deleted User" contributions. The content stays, but your personal attribution has been removed.</p>
        ${divider()}
        <p style="color: #6B7280; font-size: 0.875rem;">We're sad to see you go. If you change your mind, you're always welcome to create a new account.</p>
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 8px;"><strong>Note:</strong> If you didn't request this deletion, please contact support immediately at <a href="mailto:noreply@terp-notes.org" style="color: #E03A3C;">noreply@terp-notes.org</a></p>
    `;
    return emailWrapper(content);
}

/**
 * File Deletion Confirmation Email
 */
function fileDeletionEmail(firstname, filename) {
    const content = `
        <h2 style="color: #E03A3C; margin-top: 0;">File Deleted</h2>
        <p style="color: #374151; line-height: 1.6;">Hi ${firstname},</p>
        <p style="color: #374151; line-height: 1.6;">The file <strong>"${filename}"</strong> has been deleted from your account.</p>
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 16px;">If you didn't perform this action, please contact support immediately.</p>
    `;
    return emailWrapper(content);
}

/**
 * Bulk File Deletion Confirmation Email
 */
function bulkFileDeletionEmail(firstname, filenames) {
    const fileList = filenames.map(filename => `<li><strong>"${filename}"</strong></li>`).join('');
    const fileCount = filenames.length;

    const content = `
        <h2 style="color: #E03A3C; margin-top: 0;">Files Deleted</h2>
        <p style="color: #374151; line-height: 1.6;">Hi ${firstname},</p>
        <p style="color: #374151; line-height: 1.6;">${fileCount} file${fileCount > 1 ? 's have' : ' has'} been deleted from your account:</p>
        <ul style="color: #374151; line-height: 1.6; margin: 16px 0; padding-left: 20px;">
            ${fileList}
        </ul>
        <p style="color: #6B7280; font-size: 0.875rem; margin-top: 16px;">If you didn't perform this action, please contact support immediately.</p>
    `;
    return emailWrapper(content);
}

/**
 * File Upload Success Email
 */
function uploadSuccessEmail(firstname, fileCount, classCode) {
    const content = `
        <h2 style="color: #10B981; margin-top: 0;">Upload Successful!</h2>
        <p style="color: #374151; line-height: 1.6;">Hello ${firstname},</p>
        <p style="color: #374151; line-height: 1.6;">You successfully uploaded <strong>${fileCount} file(s)</strong> to <strong>${classCode}</strong>.</p>
        <p style="color: #374151; line-height: 1.6;">Thanks for contributing to the Terp Notes community! Your files are now available to help fellow Terps succeed.</p>
    `;
    return emailWrapper(content);
}

/**
 * Contact Form Notification Email (to admin)
 */
function contactFormEmail(name, email, subject, message) {
    const content = `
        <h2 style="color: #E03A3C; margin-top: 0;">New Support Request</h2>
        <p style="color: #374151; line-height: 1.6;"><strong>From:</strong> ${name} (${email})</p>
        <p style="color: #374151; line-height: 1.6;"><strong>Subject:</strong> ${subject}</p>
        ${divider()}
        <div style="background: #F3F4F6; padding: 16px; border-radius: 8px; margin: 16px 0;">
            <p style="color: #374151; line-height: 1.6; margin: 0; white-space: pre-wrap;">${message}</p>
        </div>
        ${divider()}
        <p style="color: #6B7280; font-size: 0.875rem;">Reply to: <a href="mailto:${email}" style="color: #E03A3C;">${email}</a></p>
    `;
    return emailWrapper(content);
}

/**
 * Admin File Deletion Notification Email
 */
function adminFileDeletionEmail(deleterInfo, fileInfo, deletionType = 'single') {
    const { firstname, lastname, email, userid, role } = deleterInfo;
    const { filename, originalName, classCode, semester, year, professor, major, category, uploadDate, downloadCount, size } = fileInfo;

    const fileSize = size ? formatFileSize(size) : 'Unknown';
    const uploadDateFormatted = uploadDate ? new Date(uploadDate).toLocaleDateString() : 'Unknown';

    const content = `
        <h2 style="color: #DC2626; margin-top: 0;">🚨 File Deletion Alert</h2>
        <p style="color: #374151; line-height: 1.6;">A file has been deleted from Terp Notes. Here are the details:</p>

        ${divider()}

        <h3 style="color: #374151; margin-top: 0;">👤 Who Deleted It</h3>
        <div style="background: #FEF2F2; padding: 16px; border-radius: 8px; margin: 16px 0; border-left: 4px solid #DC2626;">
            <p style="color: #374151; line-height: 1.6; margin: 0;"><strong>Name:</strong> ${firstname} ${lastname}</p>
            <p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Email:</strong> ${email}</p>
            <p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Username:</strong> ${userid}</p>
            <p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Role:</strong> <span style="background: #E0E7FF; color: #4338CA; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem;">${role}</span></p>
        </div>

        <h3 style="color: #374151; margin-top: 0;">📁 File Details</h3>
        <div style="background: #F3F4F6; padding: 16px; border-radius: 8px; margin: 16px 0;">
            <p style="color: #374151; line-height: 1.6; margin: 0;"><strong>Original Name:</strong> ${originalName}</p>
            <p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>File Size:</strong> ${fileSize}</p>
            <p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Upload Date:</strong> ${uploadDateFormatted}</p>
            <p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Downloads:</strong> ${downloadCount || 0}</p>
            ${classCode ? `<p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Class:</strong> ${classCode}</p>` : ''}
            ${semester && year ? `<p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Semester:</strong> ${semester} ${year}</p>` : ''}
            ${professor ? `<p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Professor:</strong> ${professor}</p>` : ''}
            ${major ? `<p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Major:</strong> ${major}</p>` : ''}
            ${category ? `<p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Category:</strong> ${category}</p>` : ''}
        </div>

        <h3 style="color: #374151; margin-top: 0;">🔍 Deletion Type</h3>
        <p style="color: #374151; line-height: 1.6;">${deletionType === 'single' ? 'Single file deletion' : `Bulk deletion (${deletionType} files)`}</p>
        
        <div style="background: #F0F9FF; padding: 16px; border-radius: 8px; margin: 16px 0; border-left: 4px solid #0EA5E9;">
            <p style="color: #374151; line-height: 1.6; margin: 0;"><strong>📎 File Attached:</strong> The deleted file has been attached to this email for your records.</p>
        </div>
        
        ${divider()}
        
        <p style="color: #6B7280; font-size: 0.875rem;">This is an automated notification to help track file deletions on the platform.</p>
    `;
    return emailWrapper(content);
}

/**
 * Admin Bulk File Deletion Notification Email
 */
function adminBulkFileDeletionEmail(deleterInfo, deletedFiles) {
    const { firstname, lastname, email, userid, role } = deleterInfo;
    const fileCount = deletedFiles.length;

    const fileList = deletedFiles.map(file => `
        <div style="background: #F3F4F6; padding: 12px; border-radius: 6px; margin: 8px 0; border-left: 3px solid #DC2626;">
            <p style="color: #374151; line-height: 1.4; margin: 0; font-weight: 600;">${file.originalName}</p>
            <div style="display: flex; gap: 12px; margin-top: 4px; font-size: 0.875rem; color: #6B7280;">
                ${file.classCode ? `<span>Class: ${file.classCode}</span>` : ''}
                ${file.semester && file.year ? `<span>${file.semester} ${file.year}</span>` : ''}
                ${file.professor ? `<span>Prof: ${file.professor}</span>` : ''}
                <span>Downloads: ${file.downloadCount || 0}</span>
            </div>
        </div>
    `).join('');

    const content = `
        <h2 style="color: #DC2626; margin-top: 0;">🚨 Bulk File Deletion Alert</h2>
        <p style="color: #374151; line-height: 1.6;"><strong>${fileCount} files</strong> have been deleted from Terp Notes in a bulk operation.</p>

        ${divider()}

        <h3 style="color: #374151; margin-top: 0;">👤 Who Deleted Them</h3>
        <div style="background: #FEF2F2; padding: 16px; border-radius: 8px; margin: 16px 0; border-left: 4px solid #DC2626;">
            <p style="color: #374151; line-height: 1.6; margin: 0;"><strong>Name:</strong> ${firstname} ${lastname}</p>
            <p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Email:</strong> ${email}</p>
            <p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Username:</strong> ${userid}</p>
            <p style="color: #374151; line-height: 1.6; margin: 4px 0 0 0;"><strong>Role:</strong> <span style="background: #E0E7FF; color: #4338CA; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem;">${role}</span></p>
        </div>

        <h3 style="color: #374151; margin-top: 0;">📁 Deleted Files (${fileCount})</h3>
        <div style="max-height: 400px; overflow-y: auto; border: 1px solid #E5E7EB; border-radius: 8px; padding: 16px; margin: 16px 0;">
            ${fileList}
        </div>
        
        <div style="background: #F0F9FF; padding: 16px; border-radius: 8px; margin: 16px 0; border-left: 4px solid #0EA5E9;">
            <p style="color: #374151; line-height: 1.6; margin: 0;"><strong>📎 Files Attached:</strong> All deleted files have been bundled into a ZIP archive and attached to this email for your records.</p>
        </div>
        
        ${divider()}
        
        <p style="color: #6B7280; font-size: 0.875rem;">This is an automated notification to help track bulk file deletions on the platform.</p>
    `;
    return emailWrapper(content);
}

// Helper function to format file size (reused from dashboard)
function formatFileSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';

    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));

    if (i === 0) return `${bytes} ${sizes[i]}`;
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}

module.exports = {
    verificationEmail,
    resendVerificationEmail,
    passwordResetEmail,
    passwordResetSuccessEmail,
    passwordChangeEmail,
    profileUpdateEmail,
    accountDeletionEmail,
    fileDeletionEmail,
    bulkFileDeletionEmail,
    uploadSuccessEmail,
    contactFormEmail,
    adminFileDeletionEmail,
    adminBulkFileDeletionEmail
};

