// Simple MVC structure that works with existing server.js
// This file is just for organization - the main server.js is still the primary entry point

const express = require('express');
const path = require('path');

// This is just a placeholder for MVC organization
// The actual server logic remains in server.js for stability

const app = express();

// Basic setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Simple route to show MVC structure is working
app.get('/mvc-test', (req, res) => {
    res.json({
        message: 'MVC structure is working!',
        timestamp: new Date().toISOString(),
        note: 'Main server logic remains in server.js for stability'
    });
});

module.exports = app;
