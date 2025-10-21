const { MongoClient } = require('mongodb');

let client = null;
let fileCollection = null;

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/terp-notes';
const DB_NAME = 'terp-notes';

async function ensureConnection() {
    if (!client) {
        try {
            client = new MongoClient(MONGODB_URI);
            await client.connect();
            console.log('✅ Connected to MongoDB');

            // Initialize file collection
            fileCollection = {
                db: DB_NAME,
                collection: 'files'
            };

            // Create indexes
            const db = client.db(DB_NAME);
            await db.collection('files').createIndex({ "uploadDate": 1 });
            await db.collection('files').createIndex({ "course": 1 });
            await db.collection('files').createIndex({ "professor": 1 });
            await db.collection('files').createIndex({ "semester": 1 });
            await db.collection('files').createIndex({ "year": 1 });
            await db.collection('files').createIndex({ "uploader": 1 });
            await db.collection('files').createIndex({ "title": "text", "description": "text" });

            console.log('Database indexes created successfully');
        } catch (error) {
            console.error('❌ MongoDB connection error:', error);
            throw error;
        }
    }
    return client;
}

async function closeConnection() {
    if (client) {
        await client.close();
        client = null;
        fileCollection = null;
        console.log('MongoDB connection closed');
    }
}

module.exports = {
    ensureConnection,
    closeConnection,
    get client() { return client; },
    get fileCollection() { return fileCollection; }
};
