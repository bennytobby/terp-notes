const tf = require('@tensorflow/tfjs-node');
const natural = require('natural');
const sentiment = require('sentiment');
const fs = require('fs').promises;
const path = require('path');

class AIProfanityFilter {
    constructor() {
        this.sentimentAnalyzer = new sentiment();
        this.tokenizer = new natural.WordTokenizer();
        this.stemmer = natural.PorterStemmer;
        this.model = null;
        this.isModelLoaded = false;
        this.isModelTrained = false;
        this.modelPath = path.join(__dirname, 'models', 'profanity-model.json');
        this.trainingDataPath = path.join(__dirname, 'models', 'training-data.json');

        // Create models directory if it doesn't exist
        this.ensureModelsDirectory();
    }

    async ensureModelsDirectory() {
        try {
            const modelsDir = path.dirname(this.modelPath);
            await fs.mkdir(modelsDir, { recursive: true });
        } catch (error) {
            console.error('❌ Failed to create models directory:', error);
        }
    }

    async initializeModel() {
        try {
            // Try to load existing model first
            if (await this.loadSavedModel()) {
                console.log('🤖 AI Profanity Filter loaded from saved model');
                return;
            }

            // Create new model if no saved model exists
            this.model = tf.sequential({
                layers: [
                    tf.layers.dense({
                        inputShape: [100], // Feature vector size
                        units: 64,
                        activation: 'relu'
                    }),
                    tf.layers.dropout({ rate: 0.3 }),
                    tf.layers.dense({
                        units: 32,
                        activation: 'relu'
                    }),
                    tf.layers.dropout({ rate: 0.3 }),
                    tf.layers.dense({
                        units: 16,
                        activation: 'relu'
                    }),
                    tf.layers.dense({
                        units: 1,
                        activation: 'sigmoid'
                    })
                ]
            });

            // Compile the model
            this.model.compile({
                optimizer: tf.train.adam(0.001),
                loss: 'binaryCrossentropy',
                metrics: ['accuracy']
            });

            this.isModelLoaded = true;
            console.log('🤖 AI Profanity Filter initialized with new model');
        } catch (error) {
            console.error('❌ Failed to initialize AI model:', error);
            this.isModelLoaded = false;
        }
    }

    async loadSavedModel() {
        try {
            // Check if model file exists
            await fs.access(this.modelPath);

            // Load the model
            this.model = await tf.loadLayersModel(`file://${this.modelPath}`);
            this.isModelLoaded = true;
            this.isModelTrained = true;

            console.log('✅ Loaded saved AI model');
            return true;
        } catch (error) {
            console.log('📝 No saved model found, will create new one');
            return false;
        }
    }

    async saveModel() {
        if (!this.model || !this.isModelTrained) {
            return false;
        }

        try {
            await this.model.save(`file://${this.modelPath}`);
            console.log('💾 AI model saved successfully');
            return true;
        } catch (error) {
            console.error('❌ Failed to save AI model:', error);
            return false;
        }
    }

    // Extract features from text for ML model
    extractFeatures(text) {
        const tokens = this.tokenizer.tokenize(text.toLowerCase());
        const features = new Array(100).fill(0);

        // Feature 1: Sentiment analysis
        const sentimentResult = this.sentimentAnalyzer.analyze(text);
        features[0] = sentimentResult.score / 10; // Normalize to -1 to 1
        features[1] = sentimentResult.comparative;

        // Feature 2: Text statistics
        features[2] = text.length / 100; // Normalized length
        features[3] = tokens.length / 20; // Normalized token count
        features[4] = (text.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g) || []).length / 10; // Punctuation density

        // Feature 3: Capitalization patterns
        features[5] = (text.match(/[A-Z]/g) || []).length / text.length; // Capital letter ratio
        features[6] = text === text.toUpperCase() ? 1 : 0; // All caps flag
        features[7] = text === text.toLowerCase() ? 1 : 0; // All lowercase flag

        // Feature 4: Word patterns
        features[8] = tokens.some(token => token.length > 10) ? 1 : 0; // Has long words
        features[9] = tokens.some(token => /^\d+$/.test(token)) ? 1 : 0; // Has numbers

        // Feature 5: Profanity indicators (enhanced)
        const profanityIndicators = [
            'fuck', 'shit', 'damn', 'bitch', 'ass', 'dick', 'cock', 'pussy', 'cunt',
            'nigger', 'fag', 'gay', 'retard', 'stupid', 'idiot', 'moron', 'slut',
            'whore', 'bastard', 'asshole', 'motherfucker', 'fucking', 'shitty'
        ];

        let profanityScore = 0;
        tokens.forEach(token => {
            profanityIndicators.forEach(indicator => {
                if (token.includes(indicator) || indicator.includes(token)) {
                    profanityScore += 1;
                }
            });
        });
        features[10] = profanityScore / 10;

        // Feature 6: Context clues
        features[11] = text.includes('?') ? 1 : 0; // Question mark
        features[12] = text.includes('!') ? 1 : 0; // Exclamation mark
        features[13] = text.includes('...') ? 1 : 0; // Ellipsis
        features[14] = (text.match(/[A-Z]{2,}/g) || []).length > 0 ? 1 : 0; // Multiple caps

        // Feature 7: Linguistic features
        const vowels = (text.match(/[aeiouAEIOU]/g) || []).length;
        const consonants = (text.match(/[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]/g) || []).length;
        features[15] = vowels / (vowels + consonants || 1); // Vowel ratio

        // Feature 8: Word frequency analysis
        const wordFreq = {};
        tokens.forEach(token => {
            wordFreq[token] = (wordFreq[token] || 0) + 1;
        });
        features[16] = Object.keys(wordFreq).length / tokens.length; // Vocabulary diversity

        // Feature 9: Character patterns
        features[17] = (text.match(/(.)\1{2,}/g) || []).length; // Repeated characters
        features[18] = (text.match(/[0-9]/g) || []).length / text.length; // Number ratio

        // Feature 10: Advanced text analysis
        features[19] = text.split(' ').filter(word => word.length > 0).length; // Word count
        features[20] = (text.match(/[.!?]/g) || []).length; // Sentence endings

        // Fill remaining features with additional patterns
        for (let i = 21; i < 100; i++) {
            features[i] = Math.random() * 0.1; // Small random values for model stability
        }

        return features;
    }

    // Predict profanity using ML model (with lazy loading)
    async predictProfanity(text) {
        // Ensure model is ready before prediction
        await this.ensureModelReady();

        if (!this.isModelLoaded || !this.isModelTrained) {
            return { confidence: 0, prediction: 'clean' };
        }

        try {
            const features = this.extractFeatures(text);
            const input = tf.tensor2d([features]);

            const prediction = await this.model.predict(input).data();
            const confidence = prediction[0];

            input.dispose();

            return {
                confidence: confidence,
                prediction: confidence > 0.5 ? 'profane' : 'clean',
                features: features.slice(0, 21) // Return first 21 meaningful features
            };
        } catch (error) {
            console.error('❌ ML prediction error:', error);
            return { confidence: 0, prediction: 'clean' };
        }
    }

    // Enhanced profanity detection combining rule-based and ML
    async detectProfanity(text) {
        const results = {
            text: text,
            ruleBased: null,
            mlBased: null,
            hybrid: null,
            confidence: 0
        };

        // Rule-based detection (existing system)
        const ruleBasedResult = this.ruleBasedDetection(text);
        results.ruleBased = ruleBasedResult;

        // ML-based detection
        const mlResult = await this.predictProfanity(text);
        results.mlBased = mlResult;

        // Hybrid decision
        if (ruleBasedResult.found) {
            results.hybrid = {
                found: true,
                method: 'rule-based',
                confidence: 0.9,
                entry: ruleBasedResult.entry
            };
        } else if (mlResult.prediction === 'profane' && mlResult.confidence > 0.7) {
            results.hybrid = {
                found: true,
                method: 'ml-based',
                confidence: mlResult.confidence,
                entry: {
                    id: 'ml-detected',
                    severity: Math.round(mlResult.confidence * 4),
                    tags: ['ml-detected'],
                    match: text
                }
            };
        } else {
            results.hybrid = {
                found: false,
                method: 'both-clean',
                confidence: 1 - mlResult.confidence
            };
        }

        results.confidence = results.hybrid.confidence;
        return results;
    }

    // Rule-based detection (existing system)
    ruleBasedDetection(text) {
        // This would call the existing containsOffensiveContent function
        // For now, return a mock result
        return { found: false, entry: null };
    }

    // Train the model with sample data (only if not already trained)
    async trainModel(trainingData) {
        if (!this.isModelLoaded || this.isModelTrained) {
            return;
        }

        try {
            const xs = [];
            const ys = [];

            trainingData.forEach(item => {
                const features = this.extractFeatures(item.text);
                xs.push(features);
                ys.push(item.isProfane ? 1 : 0);
            });

            const xTensor = tf.tensor2d(xs);
            const yTensor = tf.tensor2d(ys, [ys.length, 1]);

            await this.model.fit(xTensor, yTensor, {
                epochs: 50,
                batchSize: 32,
                validationSplit: 0.2,
                verbose: 0 // Reduced verbosity for production
            });

            xTensor.dispose();
            yTensor.dispose();

            this.isModelTrained = true;
            await this.saveModel(); // Save the trained model

            console.log('🤖 Model training completed and saved');
        } catch (error) {
            console.error('❌ Training error:', error);
        }
    }

    // Lazy initialization - only train if needed
    async ensureModelReady() {
        if (!this.isModelLoaded) {
            await this.initializeModel();
        }

        if (this.isModelLoaded && !this.isModelTrained) {
            const trainingData = this.generateTrainingData();
            await this.trainModel(trainingData);
        }
    }

    // Generate sample training data
    generateTrainingData() {
        return [
            // Clean examples
            { text: "Hello world", isProfane: false },
            { text: "How are you today?", isProfane: false },
            { text: "This is a great project", isProfane: false },
            { text: "Thank you for your help", isProfane: false },
            { text: "Have a nice day", isProfane: false },
            { text: "I love programming", isProfane: false },
            { text: "The weather is nice", isProfane: false },
            { text: "My name is John", isProfane: false },
            { text: "This is amazing", isProfane: false },
            { text: "Good morning everyone", isProfane: false },

            // Profane examples
            { text: "fuck you", isProfane: true },
            { text: "you are a bitch", isProfane: true },
            { text: "this is shit", isProfane: true },
            { text: "damn it", isProfane: true },
            { text: "you idiot", isProfane: true },
            { text: "stupid moron", isProfane: true },
            { text: "fucking hell", isProfane: true },
            { text: "you asshole", isProfane: true },
            { text: "this is bullshit", isProfane: true },
            { text: "you fucking idiot", isProfane: true }
        ];
    }
}

module.exports = AIProfanityFilter;
