const express = require('express');
const router = express.Router();
const { SelfImprovingMLFilter } = require('../models/self-improving-ml-filter');

// Admin Dashboard Routes
router.get('/admin', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.redirect('/login');
    }
    res.render('admin', {
        title: "Admin Dashboard - Terp Notes",
        user: req.session.user
    });
});

// API: Get ML Model Performance Statistics
router.get('/api/admin/ml-model-performance', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        if (!global.aiFilter) {
            return res.json({
                success: false,
                error: 'ML Model not initialized',
                modelReady: false
            });
        }

        // Get performance statistics from the model
        const performanceStats = await global.aiFilter.getPerformanceStats();

        // Get model information
        const modelInfo = {
            isModelReady: global.aiFilter.isModelReady,
            modelPath: global.aiFilter.modelPath,
            trainingLogPath: global.aiFilter.trainingLogPath,
            maxTrainingExamples: global.aiFilter.maxTrainingExamples
        };

        // Get training log if available
        let trainingLog = null;
        try {
            const fs = require('fs').promises;
            const trainingLogData = await fs.readFile(global.aiFilter.trainingLogPath, 'utf8');
            trainingLog = JSON.parse(trainingLogData);
        } catch (error) {
            // Training log not available yet
        }

        res.json({
            success: true,
            modelInfo: modelInfo,
            performanceStats: performanceStats,
            trainingLog: trainingLog,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error getting ML model performance:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get model performance statistics'
        });
    }
});

// API: Test ML Model with Sample Text
router.post('/api/admin/test-ml-model', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        const { testText } = req.body;

        if (!testText || typeof testText !== 'string') {
            return res.status(400).json({
                success: false,
                error: 'Test text is required'
            });
        }

        if (!global.aiFilter) {
            return res.json({
                success: false,
                error: 'ML Model not initialized'
            });
        }

        // Test the model with the provided text
        const result = await global.aiFilter.detectProfanity(testText, 'admin-test');

        res.json({
            success: true,
            testText: testText,
            result: result,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error testing ML model:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to test ML model'
        });
    }
});

// API: Submit Admin Feedback for ML Model
router.post('/api/admin/ml-model-feedback', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        const { testText, modelDecision, adminFeedback, mlPrediction, ruleBasedDecision, agreement } = req.body;

        if (!testText || !adminFeedback) {
            return res.status(400).json({
                success: false,
                error: 'Test text and feedback are required'
            });
        }

        if (!global.aiFilter) {
            return res.json({
                success: false,
                error: 'ML Model not initialized'
            });
        }

        // Create feedback record
        const feedbackRecord = {
            testText: testText,
            modelDecision: modelDecision,
            adminFeedback: adminFeedback,
            mlPrediction: mlPrediction,
            ruleBasedDecision: ruleBasedDecision,
            agreement: agreement,
            adminId: req.session.user.userid,
            timestamp: new Date().toISOString(),
            feedbackType: 'admin_correction'
        };

        // Store feedback in database for analysis
        // Note: Database connection would be handled here in production
        console.log('📝 Feedback recorded:', feedbackRecord);

        // If admin says the model was wrong, add this as a training example
        if (adminFeedback === 'wrong') {
            // Create a training example with the correct decision
            const correctDecision = !modelDecision; // Flip the model's decision

            console.log(`🔄 Admin feedback: Model was wrong. Correcting decision from ${modelDecision} to ${correctDecision}`);

            // Add to model's training data
            const features = global.aiFilter.extractFeatures(testText);
            console.log(`🔍 Features extracted: ${features.filter(f => f > 0).length} active features`);

            await global.aiFilter.addTrainingExample(testText, features, correctDecision, {
                adminFeedback: adminFeedback,
                originalModelDecision: modelDecision,
                adminId: req.session.user.userid,
                timestamp: new Date().toISOString(),
                feedbackType: 'admin_correction'
            });

            console.log(`✅ Training example added. Total examples: ${global.aiFilter.trainingExamples.length}`);

            // Only retrain if we have enough examples and it's been a while
            if (global.aiFilter.trainingExamples.length >= 20 && global.aiFilter.trainingExamples.length % 10 === 0) {
                console.log(`🔄 Triggering model retraining after ${global.aiFilter.trainingExamples.length} examples...`);
                await global.aiFilter.retrainModel();
            } else {
                console.log(`📝 Training example added. Will retrain at ${Math.ceil(global.aiFilter.trainingExamples.length / 10) * 10} examples.`);
            }
        }

        res.json({
            success: true,
            message: 'Feedback recorded successfully',
            feedbackId: feedbackRecord._id,
            timestamp: feedbackRecord.timestamp
        });
    } catch (error) {
        console.error('Error submitting ML model feedback:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to submit feedback'
        });
    }
});

// API: Reset ML Model
router.post('/api/admin/reset-ml-model', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        if (!global.aiFilter) {
            return res.json({
                success: false,
                error: 'ML Model not initialized'
            });
        }

        await global.aiFilter.resetModel();

        res.json({
            success: true,
            message: 'ML Model reset successfully with improved initialization',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error resetting ML model:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to reset ML model'
        });
    }
});

// API: Clear Conflicting Training Data
router.post('/api/admin/clear-ml-conflicts', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        if (!global.aiFilter) {
            return res.json({
                success: false,
                error: 'ML Model not initialized'
            });
        }

        await global.aiFilter.clearConflictingData();

        res.json({
            success: true,
            message: 'Conflicting training data cleared successfully',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error clearing conflicting data:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to clear conflicting data'
        });
    }
});

// API: Get Reinforcement Learning Statistics
router.get('/api/admin/ml-learning-stats', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        if (!global.aiFilter) {
            return res.json({
                success: false,
                error: 'ML Model not initialized'
            });
        }

        const learningStats = global.aiFilter.getLearningStats();

        res.json({
            success: true,
            learningStats: learningStats,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error getting learning stats:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get learning statistics'
        });
    }
});

module.exports = router;
