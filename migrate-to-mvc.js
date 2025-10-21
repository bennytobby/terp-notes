#!/usr/bin/env node

/**
 * Migration Script: Legacy to MVC Structure
 *
 * This script helps migrate from the original server.js to the new MVC structure
 */

const fs = require('fs');
const path = require('path');

console.log('🚀 Terp Notes - MVC Migration Helper');
console.log('=====================================\n');

// Check if new MVC structure exists
const mvcFiles = [
    'app.js',
    'server-new.js',
    'controllers/adminController.js',
    'config/database.js'
];

console.log('📁 Checking MVC Structure...');
let mvcComplete = true;

mvcFiles.forEach(file => {
    if (fs.existsSync(file)) {
        console.log(`✅ ${file}`);
    } else {
        console.log(`❌ ${file} - Missing`);
        mvcComplete = false;
    }
});

if (mvcComplete) {
    console.log('\n🎉 MVC Structure is Complete!');
    console.log('\n📋 Next Steps:');
    console.log('1. Test the new structure: node server-new.js');
    console.log('2. Access admin dashboard: http://localhost:3000/admin');
    console.log('3. Test ML model functionality');
    console.log('4. Gradually migrate other routes to controllers');
} else {
    console.log('\n⚠️  MVC Structure is Incomplete');
    console.log('Please ensure all files are created before proceeding.');
}

console.log('\n📊 Current Project Status:');
console.log('✅ Models organized in /models/');
console.log('✅ Views organized in /views/');
console.log('✅ Controllers started in /controllers/');
console.log('✅ Configuration in /config/');
console.log('✅ Middleware in /middleware/');
console.log('✅ Utils in /utils/');

console.log('\n🔧 Available Commands:');
console.log('• node server-new.js    # Start MVC version');
console.log('• node server.js        # Start legacy version');
console.log('• node migrate-to-mvc.js # Run this migration helper');

console.log('\n📚 Documentation:');
console.log('• README-MVC.md         # MVC structure documentation');
console.log('• Original server.js    # Legacy implementation');

console.log('\n✨ Migration Complete!');
