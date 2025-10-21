const fs = require('fs').promises;
const path = require('path');
const { enhancedRuleBasedDetection } = require('./enhanced-rule-based-filter');

class SelfImprovingMLFilter {
    constructor() {
        this.modelPath = path.join(__dirname, 'models', 'self-improving-model.json');
        this.trainingLogPath = path.join(__dirname, 'models', 'training-log.json');
        this.model = null;
        this.isModelReady = false;

        // Training data collection for continuous learning
        this.trainingExamples = [];
        this.maxTrainingExamples = 1000; // Limit to prevent memory issues

        // Performance tracking
        this.performanceMetrics = {
            totalPredictions: 0,
            correctPredictions: 0,
            ruleBasedAgreements: 0,
            ruleBasedDisagreements: 0,
            lastUpdated: new Date().toISOString()
        };

        // Reinforcement Learning specific properties
        this.learningHistory = [];
        this.rewardBuffer = [];
        this.explorationRate = 0.1; // Start with 10% exploration
        this.learningRate = 0.01;
        this.discountFactor = 0.95; // How much future rewards matter
        this.episodeCount = 0;
        this.successStreak = 0;
        this.failureStreak = 0;
        this.qTable = new Map(); // Q-learning table for state-action pairs
    }

    async ensureModelReady() {
        if (!this.isModelReady) {
            try {
                await this.loadModel();
                await this.loadTrainingLog(); // Load performance metrics
                this.isModelReady = true;
            } catch (error) {
                console.log('📝 No saved model found, will create new one');
                await this.initializeModel();
                this.isModelReady = true;
            }
        }
    }

    async initializeModel() {
        // Initialize model with random weights
        this.model = {
            weights: this.generateRandomWeights(),
            bias: (Math.random() - 0.5) * 0.1, // Small random bias
            trainingAccuracy: 0,
            testAccuracy: 0,
            trainingExamples: 0,
            ruleBasedAgreements: 0
        };

        await this.saveModel();
        console.log('🤖 Self-improving ML model initialized');
        console.log(`📊 Initial weights range: ${Math.min(...this.model.weights).toFixed(3)} to ${Math.max(...this.model.weights).toFixed(3)}`);
        console.log(`📊 Initial bias: ${this.model.bias.toFixed(3)}`);
    }

    async detectProfanity(text, endpoint = 'unknown') {
        await this.ensureModelReady();

        // Step 1: ML Model makes prediction first
        const features = this.extractFeatures(text);
        const mlPrediction = this.predict(features);
        const mlDecision = mlPrediction > 0.5;

        // Step 2: Rule-based system makes decision
        const ruleBasedResult = enhancedRuleBasedDetection(text);
        const ruleBasedDecision = ruleBasedResult.found;

        // Step 3: Use rule-based decision as ground truth for learning
        const groundTruth = ruleBasedDecision;

        // Step 4: Track agreement/disagreement
        this.performanceMetrics.totalPredictions++;
        if (mlDecision === ruleBasedDecision) {
            this.performanceMetrics.ruleBasedAgreements++;
            this.performanceMetrics.correctPredictions++;
        } else {
            this.performanceMetrics.ruleBasedDisagreements++;
            // ML was wrong, rule-based was right - this is a learning opportunity
        }

        // Save metrics after each prediction
        await this.saveTrainingLog();

        // Step 5: Add to training data for continuous learning
        await this.addTrainingExample(text, features, groundTruth, {
            mlPrediction: mlPrediction,
            ruleBasedDecision: ruleBasedDecision,
            endpoint: endpoint,
            timestamp: new Date().toISOString()
        });

        // Step 6: Return rule-based decision as final result (trust the rules)
        // But also include ML prediction for transparency
        return {
            text: text,
            finalDecision: ruleBasedDecision,
            method: 'rule-based-guided',
            confidence: ruleBasedDecision ? 1.0 : (1 - mlPrediction),
            mlPrediction: mlPrediction,
            mlDecision: mlDecision,
            ruleBasedResult: ruleBasedResult,
            agreement: mlDecision === ruleBasedDecision,
            learningData: {
                mlConfidence: mlPrediction,
                ruleBasedConfidence: ruleBasedResult.found ? 1.0 : 0.0,
                disagreement: mlDecision !== ruleBasedDecision
            }
        };
    }

    async addTrainingExample(text, features, groundTruth, metadata) {
        // Add to training examples
        this.trainingExamples.push({
            text: text,
            features: features,
            groundTruth: groundTruth,
            metadata: metadata
        });

        // Limit training examples to prevent memory issues
        if (this.trainingExamples.length > this.maxTrainingExamples) {
            this.trainingExamples = this.trainingExamples.slice(-this.maxTrainingExamples);
        }

        // Apply Reinforcement Learning
        await this.applyReinforcementLearning({
            text: text,
            features: features,
            groundTruth: groundTruth,
            metadata: metadata
        });

        // Periodic retraining when we have enough new examples
        // Only retrain every 10 examples to avoid overfitting
        if (this.trainingExamples.length % 10 === 0 && this.trainingExamples.length > 20) {
            await this.retrainModel();
        }

        // Save training log
        await this.saveTrainingLog();
    }

    async retrainModel() {
        if (this.trainingExamples.length < 10) {
            return; // Need minimum examples for meaningful training
        }

        console.log(`🔄 Retraining model with ${this.trainingExamples.length} examples...`);

        const epochs = 100; // More epochs for better learning
        let learningRate = 0.01; // Higher learning rate for faster convergence
        let finalCorrect = 0; // Track final accuracy

        for (let epoch = 0; epoch < epochs; epoch++) {
            let totalLoss = 0;
            let correct = 0;

            // Shuffle training examples
            const shuffledExamples = [...this.trainingExamples].sort(() => Math.random() - 0.5);

            for (const example of shuffledExamples) {
                const prediction = this.predict(example.features);
                const target = example.groundTruth ? 1 : 0;

                const loss = this.calculateLoss(prediction, target);
                totalLoss += loss;

                if ((prediction > 0.5) === example.groundTruth) {
                    correct++;
                }

                // Update weights
                this.updateWeights(example.features, prediction, target, learningRate);
            }

            const avgLoss = totalLoss / this.trainingExamples.length;
            const accuracy = (correct / this.trainingExamples.length) * 100;

            // Store final accuracy from last epoch
            finalCorrect = correct;

            // Learning rate decay
            if (epoch % 10 === 0) {
                learningRate *= 0.95;
            }

            // Early stopping if accuracy is high
            if (accuracy > 95 && avgLoss < 0.1) {
                break;
            }
        }

        // Update model statistics
        this.model.trainingExamples = this.trainingExamples.length;
        this.model.ruleBasedAgreements = this.performanceMetrics.ruleBasedAgreements;
        this.model.trainingAccuracy = (finalCorrect / this.trainingExamples.length) * 100;

        await this.saveModel();
        console.log(`✅ Model retrained. Accuracy: ${this.model.trainingAccuracy.toFixed(2)}%`);
    }

    extractFeatures(text) {
        const features = new Array(60).fill(0);

        // Basic profanity detection - expanded list
        features[0] = /fuck|shit|damn|bitch|ass|dick|cock|pussy|cunt|whore|slut|bastard|motherfucker|clit|clitoris|penis|vagina|boob|tits|fag|faggot|nigger|nazi|hitler/i.test(text) ? 1 : 0;

        // Word patterns
        features[1] = /fucking|shitting|damning|bitching|asshole|dickhead|cocky|pussied|cunted|whoring|slutting|bastarding/i.test(text) ? 1 : 0;

        // Symbol substitutions
        features[2] = /f\*ck|sh\*t|d\*mn|b\*tch|a\$\$|d\*ck|c\*ck|p\*ssy|c\*nt|wh\*re|sl\*t/i.test(text) ? 1 : 0;
        features[3] = /f\*\*k|sh\*\*t|d\*\*n|b\*\*ch|a\$\$|d\*\*k|c\*\*k|p\*\*sy|c\*\*t|wh\*\*e|sl\*\*t/i.test(text) ? 1 : 0;

        // Number substitutions
        features[4] = /f0ck|sh1t|d4mn|b1tch|a55|d1ck|c0ck|p4ssy|c4nt|wh0re|sl4t/i.test(text) ? 1 : 0;
        features[5] = /f\*\*k|sh\*\*t|d\*\*n|b\*\*ch|a\$\$|d\*\*k|c\*\*k|p\*\*sy|c\*\*t|wh\*\*e|sl\*\*t/i.test(text) ? 1 : 0;

        // Character substitutions
        features[6] = /f@ck|sh!t|d@mn|b!tch|@ss|d!ck|c0ck|p@ssy|c@nt|wh0re|sl@t/i.test(text) ? 1 : 0;
        features[7] = /f#ck|sh#t|d#mn|b#tch|#ss|d#ck|c#ck|p#ssy|c#nt|wh#re|sl#t/i.test(text) ? 1 : 0;

        // Leet speak
        features[8] = /fuk|sh1t|damn|b1tch|ass|d1ck|c0ck|pussy|cunt|wh0re|slut/i.test(text) ? 1 : 0;
        features[9] = /fuq|sh1t|damn|b1tch|ass|d1ck|c0ck|pussy|cunt|wh0re|slut/i.test(text) ? 1 : 0;

        // Repeated characters
        features[10] = /f+u+c+k+|s+h+i+t+|d+a+m+n+|b+i+t+c+h+/i.test(text) ? 1 : 0;
        features[11] = /a+s+s+|d+i+c+k+|c+o+c+k+|p+u+s+s+y+/i.test(text) ? 1 : 0;

        // Context patterns
        features[12] = /you.*fuck|fuck.*you/i.test(text) ? 1 : 0;
        features[13] = /this.*shit|shit.*this/i.test(text) ? 1 : 0;
        features[14] = /what.*damn|damn.*what/i.test(text) ? 1 : 0;
        features[15] = /stupid.*bitch|bitch.*stupid/i.test(text) ? 1 : 0;

        // Academic/Technical context (should be false)
        features[16] = /classic.*music|music.*classic/i.test(text) ? 1 : 0;
        features[17] = /massive.*project|project.*massive/i.test(text) ? 1 : 0;
        features[18] = /assistance.*program|program.*assistance/i.test(text) ? 1 : 0;
        features[19] = /penicillin.*notes|notes.*penicillin/i.test(text) ? 1 : 0;
        features[20] = /analytical.*thinking|thinking.*analytical/i.test(text) ? 1 : 0;

        // File extensions
        features[21] = /\.pdf|\.docx|\.pptx|\.xlsx|\.txt|\.zip/i.test(text) ? 1 : 0;

        // Text statistics
        features[22] = text.length > 50 ? 1 : 0;
        features[23] = text.split(' ').length > 5 ? 1 : 0;
        features[24] = /[A-Z]/.test(text) ? 1 : 0;
        features[25] = /[0-9]/.test(text) ? 1 : 0;
        features[26] = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(text) ? 1 : 0;

        // Word frequency
        const words = text.toLowerCase().split(/\s+/);
        const wordCounts = {};
        words.forEach(word => {
            wordCounts[word] = (wordCounts[word] || 0) + 1;
        });
        features[27] = Math.max(...Object.values(wordCounts)) > 2 ? 1 : 0;

        // Character patterns
        features[28] = /(.)\1{2,}/.test(text) ? 1 : 0; // Repeated characters
        features[29] = /[aeiou]{3,}/i.test(text) ? 1 : 0; // Multiple vowels
        features[30] = /[bcdfghjklmnpqrstvwxyz]{4,}/i.test(text) ? 1 : 0; // Multiple consonants

        // Username patterns
        features[31] = /user$|user\d+/i.test(text) ? 1 : 0;
        features[32] = /^[a-z]+\d+$/i.test(text) ? 1 : 0;

        // Positive context profanity
        features[33] = /fucking.*awesome|fucking.*amazing|fucking.*great|fucking.*brilliant/i.test(text) ? 1 : 0;
        features[34] = /fucking.*assignment|fucking.*project|fucking.*homework/i.test(text) ? 1 : 0;
        features[35] = /fucking.*content|fucking.*work|fucking.*job/i.test(text) ? 1 : 0;
        features[36] = /fucking.*solution|fucking.*result|fucking.*performance/i.test(text) ? 1 : 0;

        // Username profanity patterns
        features[37] = /user.*fuck|fuck.*user/i.test(text) ? 1 : 0;
        features[38] = /bitch.*user|user.*bitch/i.test(text) ? 1 : 0;
        features[39] = /damn.*user|user.*damn/i.test(text) ? 1 : 0;
        features[40] = /shit.*user|user.*shit/i.test(text) ? 1 : 0;
        features[41] = /ass.*user|user.*ass/i.test(text) ? 1 : 0;
        features[42] = /dick.*user|user.*dick/i.test(text) ? 1 : 0;
        features[43] = /cock.*user|user.*cock/i.test(text) ? 1 : 0;
        features[44] = /pussy.*user|user.*pussy/i.test(text) ? 1 : 0;
        features[45] = /cunt.*user|user.*cunt/i.test(text) ? 1 : 0;
        features[46] = /whore.*user|user.*whore/i.test(text) ? 1 : 0;
        features[47] = /slut.*user|user.*slut/i.test(text) ? 1 : 0;

        // File extension + profanity patterns
        features[48] = /fuck.*pdf|pdf.*fuck/i.test(text) ? 1 : 0;
        features[49] = /shit.*docx|docx.*shit/i.test(text) ? 1 : 0;
        features[50] = /damn.*txt|txt.*damn/i.test(text) ? 1 : 0;
        features[51] = /bitch.*zip|zip.*bitch/i.test(text) ? 1 : 0;
        features[52] = /ass.*pptx|pptx.*ass/i.test(text) ? 1 : 0;
        features[53] = /cock.*xlsx|xlsx.*cock/i.test(text) ? 1 : 0;
        features[54] = /pussy.*doc|doc.*pussy/i.test(text) ? 1 : 0;
        features[55] = /cunt.*ppt|ppt.*cunt/i.test(text) ? 1 : 0;
        features[56] = /whore.*xls|xls.*whore/i.test(text) ? 1 : 0;
        features[57] = /slut.*csv|csv.*slut/i.test(text) ? 1 : 0;

        // Additional context patterns
        features[58] = /fuck.*this|this.*fuck/i.test(text) ? 1 : 0;
        features[59] = /shit.*homework|homework.*shit/i.test(text) ? 1 : 0;

        // Add some general text analysis features
        // These will help the model learn patterns even when specific profanity isn't detected
        const textWords = text.toLowerCase().split(/\s+/);
        const totalWords = textWords.length;

        // Check for suspicious word patterns
        const suspiciousPatterns = [
            /clit/i, /penis/i, /vagina/i, /boob/i, /tits/i, /fag/i, /nigger/i, /nazi/i, /hitler/i,
            /sex/i, /porn/i, /xxx/i, /nude/i, /naked/i, /horny/i, /sexy/i, /hot/i
        ];

        let suspiciousCount = 0;
        suspiciousPatterns.forEach(pattern => {
            if (pattern.test(text)) suspiciousCount++;
        });

        // Add these as additional features if we have space
        if (features.length > 60) {
            features[60] = suspiciousCount > 0 ? 1 : 0;
            features[61] = totalWords < 3 ? 1 : 0; // Very short text might be profanity
            features[62] = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{3,}/.test(text) ? 1 : 0; // Lots of symbols
        }

        return features;
    }

    generateRandomWeights() {
        const weights = [];
        for (let i = 0; i < 60; i++) {
            // Use Xavier/Glorot initialization for better weight distribution
            const xavier = Math.sqrt(2.0 / 60); // 60 is the number of features
            weights.push((Math.random() - 0.5) * 2 * xavier);
        }
        return weights;
    }

    predict(features) {
        let sum = this.model.bias;
        let activeFeatures = 0;

        for (let i = 0; i < features.length; i++) {
            if (features[i] > 0) {
                sum += features[i] * this.model.weights[i];
                activeFeatures++;
            }
        }

        const rawScore = sum;
        const prediction = 1 / (1 + Math.exp(-sum)); // Sigmoid activation

        // Debug logging for first few predictions
        if (this.performanceMetrics.totalPredictions < 5) {
            console.log(`🔍 ML Debug - Text features: ${activeFeatures} active, Raw score: ${rawScore.toFixed(3)}, Prediction: ${(prediction * 100).toFixed(1)}%`);
        }

        return prediction;
    }

    calculateLoss(prediction, target) {
        // Binary cross-entropy loss
        const epsilon = 1e-15;
        const clippedPrediction = Math.max(epsilon, Math.min(1 - epsilon, prediction));
        return -(target * Math.log(clippedPrediction) + (1 - target) * Math.log(1 - clippedPrediction));
    }

    updateWeights(features, prediction, target, learningRate) {
        const error = prediction - target;

        // Update bias
        this.model.bias -= learningRate * error;

        // Update weights
        for (let i = 0; i < features.length; i++) {
            this.model.weights[i] -= learningRate * error * features[i];
        }
    }

    async saveModel() {
        try {
            await fs.mkdir(path.dirname(this.modelPath), { recursive: true });
            await fs.writeFile(this.modelPath, JSON.stringify(this.model, null, 2));
        } catch (error) {
            console.error('Error saving model:', error);
        }
    }

    async loadModel() {
        try {
            const data = await fs.readFile(this.modelPath, 'utf8');
            this.model = JSON.parse(data);
        } catch (error) {
            throw new Error('Model file not found');
        }
    }

    async saveTrainingLog() {
        try {
            await fs.mkdir(path.dirname(this.trainingLogPath), { recursive: true });
            await fs.writeFile(this.trainingLogPath, JSON.stringify({
                performanceMetrics: this.performanceMetrics,
                trainingExamplesCount: this.trainingExamples.length,
                learningHistory: this.learningHistory,
                episodeCount: this.episodeCount,
                successStreak: this.successStreak,
                failureStreak: this.failureStreak,
                explorationRate: this.explorationRate,
                lastUpdated: new Date().toISOString()
            }, null, 2));
        } catch (error) {
            console.error('Error saving training log:', error);
        }
    }

    async loadTrainingLog() {
        try {
            const data = await fs.readFile(this.trainingLogPath, 'utf8');
            const logData = JSON.parse(data);

            // Restore performance metrics
            if (logData.performanceMetrics) {
                this.performanceMetrics = logData.performanceMetrics;
            }

            // Restore learning history and RL data
            if (logData.learningHistory) {
                this.learningHistory = logData.learningHistory;
            }
            if (logData.episodeCount !== undefined) {
                this.episodeCount = logData.episodeCount;
            }
            if (logData.successStreak !== undefined) {
                this.successStreak = logData.successStreak;
            }
            if (logData.failureStreak !== undefined) {
                this.failureStreak = logData.failureStreak;
            }
            if (logData.explorationRate !== undefined) {
                this.explorationRate = logData.explorationRate;
            }

            console.log(`📊 Loaded training log: ${this.performanceMetrics.totalPredictions} predictions, ${this.episodeCount} episodes`);
        } catch (error) {
            console.log('📝 No training log found, starting fresh');
        }
    }

    async getPerformanceStats() {
        return {
            totalPredictions: this.performanceMetrics.totalPredictions,
            correctPredictions: this.performanceMetrics.correctPredictions,
            accuracy: this.performanceMetrics.totalPredictions > 0 ?
                (this.performanceMetrics.correctPredictions / this.performanceMetrics.totalPredictions) * 100 : 0,
            ruleBasedAgreements: this.performanceMetrics.ruleBasedAgreements,
            ruleBasedDisagreements: this.performanceMetrics.ruleBasedDisagreements,
            agreementRate: this.performanceMetrics.totalPredictions > 0 ?
                (this.performanceMetrics.ruleBasedAgreements / this.performanceMetrics.totalPredictions) * 100 : 0,
            trainingExamples: this.trainingExamples.length
        };
    }

    // Reset model to force reinitialization with better weights
    async resetModel() {
        console.log('🔄 Resetting ML model with improved initialization...');
        this.model = null;
        this.isModelReady = false;
        this.trainingExamples = [];
        this.performanceMetrics = {
            totalPredictions: 0,
            correctPredictions: 0,
            ruleBasedAgreements: 0,
            ruleBasedDisagreements: 0,
            lastUpdated: new Date().toISOString()
        };
        await this.initializeModel();
        console.log('✅ Model reset complete');
    }

    // Clear conflicting training data
    async clearConflictingData() {
        console.log('🧹 Clearing potentially conflicting training data...');

        // Keep only the most recent 20 examples to avoid conflicts
        if (this.trainingExamples.length > 20) {
            this.trainingExamples = this.trainingExamples.slice(-20);
            console.log(`📝 Kept only the most recent 20 training examples`);
        }

        // Reset performance metrics
        this.performanceMetrics = {
            totalPredictions: 0,
            correctPredictions: 0,
            ruleBasedAgreements: 0,
            ruleBasedDisagreements: 0,
            lastUpdated: new Date().toISOString()
        };

        await this.saveTrainingLog();
        console.log('✅ Conflicting data cleared');
    }

    // Reinforcement Learning Implementation
    async applyReinforcementLearning(example) {
        this.episodeCount++;

        // Calculate reward based on admin feedback
        const reward = this.calculateReward(example);

        // Store in learning history
        this.learningHistory.push({
            episode: this.episodeCount,
            text: example.text,
            features: example.features,
            groundTruth: example.groundTruth,
            reward: reward,
            timestamp: new Date().toISOString(),
            explorationRate: this.explorationRate,
            successStreak: this.successStreak,
            failureStreak: this.failureStreak
        });

        // Update Q-table with Q-learning
        await this.updateQTable(example, reward);

        // Update exploration rate (decrease over time)
        this.updateExplorationRate();

        // Update success/failure streaks
        this.updateStreaks(reward);

        // Apply immediate weight updates based on reward
        await this.applyImmediateLearning(example, reward);

        console.log(`🧠 RL Episode ${this.episodeCount}: Reward=${reward.toFixed(3)}, Exploration=${(this.explorationRate*100).toFixed(1)}%, Success Streak=${this.successStreak}`);
    }

    calculateReward(example) {
        // Reward structure for reinforcement learning
        let reward = 0;

        if (example.metadata && example.metadata.adminFeedback) {
            switch (example.metadata.adminFeedback) {
                case 'correct':
                    reward = 1.0; // High reward for correct predictions
                    break;
                case 'wrong':
                    reward = -1.0; // Negative reward for wrong predictions
                    break;
                case 'neutral':
                    reward = 0.1; // Small positive reward for neutral feedback
                    break;
            }
        }

        // Bonus for consistency with rule-based system
        if (example.metadata && example.metadata.agreement) {
            reward += 0.2;
        }

        // Penalty for disagreement
        if (example.metadata && example.metadata.disagreement) {
            reward -= 0.1;
        }

        return Math.max(-1, Math.min(1, reward)); // Clamp between -1 and 1
    }

    async updateQTable(example, reward) {
        // Create state representation from features
        const state = this.featuresToState(example.features);
        const action = example.groundTruth ? 1 : 0; // 1 for profanity, 0 for clean

        const stateKey = state.join(',');
        const actionKey = `${stateKey}_${action}`;

        // Get current Q-value
        const currentQ = this.qTable.get(actionKey) || 0;

        // Q-learning update: Q(s,a) = Q(s,a) + α[r + γ*max(Q(s',a')) - Q(s,a)]
        const maxFutureQ = this.getMaxFutureQ(state);
        const newQ = currentQ + this.learningRate * (reward + this.discountFactor * maxFutureQ - currentQ);

        this.qTable.set(actionKey, newQ);
    }

    featuresToState(features) {
        // Convert features to discrete state representation
        return features.map(f => f > 0 ? 1 : 0); // Binary representation
    }

    getMaxFutureQ(state) {
        // Get maximum Q-value for future states
        const stateKey = state.join(',');
        const action0Key = `${stateKey}_0`;
        const action1Key = `${stateKey}_1`;

        const q0 = this.qTable.get(action0Key) || 0;
        const q1 = this.qTable.get(action1Key) || 0;

        return Math.max(q0, q1);
    }

    updateExplorationRate() {
        // Decay exploration rate over time, but keep minimum
        this.explorationRate = Math.max(0.01, this.explorationRate * 0.995);
    }

    updateStreaks(reward) {
        if (reward > 0) {
            this.successStreak++;
            this.failureStreak = 0;
        } else if (reward < 0) {
            this.failureStreak++;
            this.successStreak = 0;
        }
    }

    async applyImmediateLearning(example, reward) {
        if (!this.model || Math.abs(reward) < 0.1) return;

        // Apply immediate weight updates based on reward
        const features = example.features;
        const target = example.groundTruth ? 1 : 0;
        const prediction = this.predict(features);

        // Calculate error
        const error = target - prediction;

        // Update weights immediately based on reward magnitude
        const updateStrength = Math.abs(reward) * this.learningRate;

        // Update bias
        this.model.bias += updateStrength * error;

        // Update weights
        for (let i = 0; i < features.length && i < this.model.weights.length; i++) {
            if (features[i] > 0) {
                this.model.weights[i] += updateStrength * error * features[i];
            }
        }

        // Save the updated model
        await this.saveModel();
    }

    // Get learning statistics
    getLearningStats() {
        const recentHistory = this.learningHistory.slice(-50); // Last 50 episodes
        const avgReward = recentHistory.reduce((sum, h) => sum + h.reward, 0) / recentHistory.length;
        const successRate = recentHistory.filter(h => h.reward > 0).length / recentHistory.length;

        return {
            episodeCount: this.episodeCount,
            explorationRate: this.explorationRate,
            successStreak: this.successStreak,
            failureStreak: this.failureStreak,
            avgReward: avgReward,
            successRate: successRate,
            qTableSize: this.qTable.size,
            learningHistorySize: this.learningHistory.length
        };
    }
}

module.exports = SelfImprovingMLFilter;
