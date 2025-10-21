const natural = require('natural');
const sentiment = require('sentiment');
const fs = require('fs').promises;
const path = require('path');

class SimpleAIProfanityFilter {
    constructor() {
        this.sentimentAnalyzer = new sentiment();
        this.tokenizer = new natural.WordTokenizer();
        this.stemmer = natural.PorterStemmer;
        this.model = null;
        this.isModelLoaded = false;
        this.modelPath = path.join(__dirname, 'models', 'simple-profanity-model.json');

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
                console.log('🤖 Simple AI Profanity Filter loaded from saved model');
                return;
            }

            // Create new simple model
            this.model = {
                weights: this.generateRandomWeights(),
                bias: Math.random() * 0.1,
                trained: false
            };

            this.isModelLoaded = true;
            console.log('🤖 Simple AI Profanity Filter initialized with new model');
        } catch (error) {
            console.error('❌ Failed to initialize simple AI model:', error);
            this.isModelLoaded = false;
        }
    }

    generateRandomWeights() {
        const weights = [];
        for (let i = 0; i < 60; i++) {
            weights.push((Math.random() - 0.5) * 0.1);
        }
        return weights;
    }

    async loadSavedModel() {
        try {
            // Check if model file exists
            await fs.access(this.modelPath);

            // Load the model
            const modelData = await fs.readFile(this.modelPath, 'utf8');
            this.model = JSON.parse(modelData);
            this.isModelLoaded = true;

            console.log('✅ Loaded saved simple AI model');
            return true;
        } catch (error) {
            console.log('📝 No saved model found, will create new one');
            return false;
        }
    }

    async saveModel() {
        if (!this.model || !this.model.trained) {
            return false;
        }

        try {
            await fs.writeFile(this.modelPath, JSON.stringify(this.model, null, 2));
            console.log('💾 Simple AI model saved successfully');
            return true;
        } catch (error) {
            console.error('❌ Failed to save simple AI model:', error);
            return false;
        }
    }

    // Extract features from text for ML model
    extractFeatures(text) {
        const tokens = this.tokenizer.tokenize(text.toLowerCase());
        const features = new Array(60).fill(0); // Expanded feature count

        // Feature 1: Sentiment analysis
        const sentimentResult = this.sentimentAnalyzer.analyze(text);
        features[0] = sentimentResult.score / 10; // Normalize to -1 to 1
        features[1] = sentimentResult.comparative;

        // Feature 2: Context analysis
        const positiveWords = ['amazing', 'awesome', 'brilliant', 'incredible', 'outstanding', 'fantastic', 'marvelous', 'spectacular', 'wonderful', 'perfect', 'excellent', 'great', 'good', 'nice', 'cool'];
        const negativeWords = ['terrible', 'awful', 'horrible', 'disgusting', 'stupid', 'idiot', 'moron', 'hate', 'suck', 'blow', 'bad', 'wrong', 'evil'];

        let positiveContext = 0;
        let negativeContext = 0;

        tokens.forEach(token => {
            if (positiveWords.includes(token)) positiveContext++;
            if (negativeWords.includes(token)) negativeContext++;
        });

        features[2] = positiveContext / tokens.length; // Positive context ratio
        features[3] = negativeContext / tokens.length; // Negative context ratio
        features[4] = (positiveContext - negativeContext) / tokens.length; // Net context sentiment

        // Feature 5: Text statistics
        features[5] = text.length / 100; // Normalized length
        features[6] = tokens.length / 20; // Normalized token count
        features[7] = (text.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g) || []).length / 10; // Punctuation density

        // Feature 8: Capitalization patterns
        features[8] = (text.match(/[A-Z]/g) || []).length / text.length; // Capital letter ratio
        features[9] = text === text.toUpperCase() ? 1 : 0; // All caps flag
        features[10] = text === text.toLowerCase() ? 1 : 0; // All lowercase flag

        // Feature 11: Word patterns
        features[11] = tokens.some(token => token.length > 10) ? 1 : 0; // Has long words
        features[12] = tokens.some(token => /^\d+$/.test(token)) ? 1 : 0; // Has numbers

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
        features[13] = profanityScore / 10;

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

        // Feature 19: Clean euphemisms detection
        const cleanEuphemisms = ['darn', 'gosh', 'heck', 'shoot', 'drat', 'blimey'];
        const hasCleanEuphemisms = cleanEuphemisms.some(euphemism => tokens.includes(euphemism));
        features[19] = hasCleanEuphemisms ? 1 : 0;

        // Feature 20: Legitimate compound words detection
        const legitimateCompounds = ['classic', 'massive', 'passionate', 'assistance', 'assessment', 'assertion', 'assignment', 'assumption', 'assurance', 'penicillin', 'analytical'];
        const hasLegitimateCompounds = legitimateCompounds.some(compound => tokens.includes(compound));
        features[20] = hasLegitimateCompounds ? 1 : 0;

        // Feature 21: Academic/medical context
        const academicWords = ['science', 'computer', 'programming', 'algorithm', 'analysis', 'research', 'study', 'antibiotic', 'medical', 'treatment'];
        const hasAcademicContext = academicWords.some(word => tokens.includes(word));
        features[21] = hasAcademicContext ? 1 : 0;

        // Feature 22: Advanced text analysis
        features[22] = text.split(' ').filter(word => word.length > 0).length; // Word count
        features[23] = (text.match(/[.!?]/g) || []).length; // Sentence endings

        // Feature 24-28: File naming patterns (upload endpoint specific)
        features[24] = text.includes('_') ? 1 : 0; // Contains underscores
        features[25] = /\.(pdf|docx|pptx|xlsx|txt|zip)$/i.test(text) ? 1 : 0; // File extension
        features[26] = /^[a-z]+_[a-z]+/i.test(text) ? 1 : 0; // snake_case pattern
        features[27] = /^\d{4}$/.test(text) ? 1 : 0; // Year pattern (2024, 2023, etc.)
        features[28] = /^[a-z]+_[a-z]+\.(pdf|docx|pptx|xlsx|txt|zip)$/i.test(text) ? 1 : 0; // File with underscores

        // Feature 29-33: Enhanced academic context
        const academicTerms = ['notes', 'assignment', 'project', 'research', 'homework', 'study', 'lecture', 'lab', 'exam', 'course', 'class', 'syllabus'];
        const hasAcademicTerms = academicTerms.some(word => tokens.includes(word));
        features[29] = hasAcademicTerms ? 1 : 0;

        const technicalTerms = ['analysis', 'data', 'program', 'system', 'algorithm', 'database', 'software', 'hardware', 'network'];
        const hasTechnicalTerms = technicalTerms.some(word => tokens.includes(word));
        features[30] = hasTechnicalTerms ? 1 : 0;

        const medicalTerms = ['penicillin', 'antibiotic', 'medical', 'treatment', 'therapy', 'diagnosis', 'surgery', 'patient'];
        const hasMedicalTerms = medicalTerms.some(word => tokens.includes(word));
        features[31] = hasMedicalTerms ? 1 : 0;

        const scientificTerms = ['analytical', 'experiment', 'hypothesis', 'theory', 'methodology', 'synthesis'];
        const hasScientificTerms = scientificTerms.some(word => tokens.includes(word));
        features[32] = hasScientificTerms ? 1 : 0;

        const educationalTerms = ['classic', 'massive', 'assistance', 'assessment', 'assumption', 'assertion'];
        const hasEducationalTerms = educationalTerms.some(word => tokens.includes(word));
        features[33] = hasEducationalTerms ? 1 : 0;

        // Feature 34-38: Enhanced context analysis for positive profanity
        features[34] = /this is.*fucking/i.test(text) ? 1 : 0; // "this is fucking" pattern
        features[35] = /fucking.*awesome|fucking.*amazing|fucking.*great|fucking.*brilliant/i.test(text) ? 1 : 0; // Positive profanity
        features[36] = /fucking.*assignment|fucking.*project|fucking.*homework/i.test(text) ? 1 : 0; // Academic profanity
        features[37] = /fucking.*content|fucking.*work|fucking.*job/i.test(text) ? 1 : 0; // Work profanity
        features[38] = /fucking.*solution|fucking.*result|fucking.*performance/i.test(text) ? 1 : 0; // Result profanity

        // Feature 39-49: CRITICAL PUBLIC-FACING PATTERNS (Usernames & Files)
        features[39] = /user.*fuck|fuck.*user/i.test(text) ? 1 : 0; // Username profanity patterns
        features[40] = /bitch.*user|user.*bitch/i.test(text) ? 1 : 0; // Username compound profanity
        features[41] = /damn.*user|user.*damn/i.test(text) ? 1 : 0; // Username profanity patterns
        features[42] = /shit.*user|user.*shit/i.test(text) ? 1 : 0; // Username profanity patterns
        features[43] = /ass.*user|user.*ass/i.test(text) ? 1 : 0; // Username profanity patterns
        features[44] = /dick.*user|user.*dick/i.test(text) ? 1 : 0; // Username profanity patterns
        features[45] = /cock.*user|user.*cock/i.test(text) ? 1 : 0; // Username profanity patterns
        features[46] = /pussy.*user|user.*pussy/i.test(text) ? 1 : 0; // Username profanity patterns
        features[47] = /cunt.*user|user.*cunt/i.test(text) ? 1 : 0; // Username profanity patterns
        features[48] = /whore.*user|user.*whore/i.test(text) ? 1 : 0; // Username profanity patterns
        features[49] = /slut.*user|user.*slut/i.test(text) ? 1 : 0; // Username profanity patterns

        // Feature 50-59: FILE UPLOAD PATTERNS (Critical Public-Facing)
        features[50] = /fuck.*pdf|pdf.*fuck/i.test(text) ? 1 : 0; // File extension + profanity
        features[51] = /shit.*docx|docx.*shit/i.test(text) ? 1 : 0; // File extension + profanity
        features[52] = /damn.*txt|txt.*damn/i.test(text) ? 1 : 0; // File extension + profanity
        features[53] = /bitch.*zip|zip.*bitch/i.test(text) ? 1 : 0; // File extension + profanity
        features[54] = /ass.*pptx|pptx.*ass/i.test(text) ? 1 : 0; // File extension + profanity
        features[55] = /cock.*xlsx|xlsx.*cock/i.test(text) ? 1 : 0; // File extension + profanity
        features[56] = /pussy.*doc|doc.*pussy/i.test(text) ? 1 : 0; // File extension + profanity
        features[57] = /cunt.*ppt|ppt.*cunt/i.test(text) ? 1 : 0; // File extension + profanity
        features[58] = /whore.*xls|xls.*whore/i.test(text) ? 1 : 0; // File extension + profanity
        features[59] = /slut.*csv|csv.*slut/i.test(text) ? 1 : 0; // File extension + profanity

        return features;
    }

    // Simple neural network prediction (without TensorFlow)
    predictProfanity(text) {
        if (!this.isModelLoaded || !this.model) {
            return { confidence: 0, prediction: 'clean' };
        }

        try {
            const features = this.extractFeatures(text);

            // Simple linear model: y = weights * features + bias
            let prediction = this.model.bias;
            for (let i = 0; i < Math.min(features.length, this.model.weights.length); i++) {
                prediction += features[i] * this.model.weights[i];
            }

            // Sigmoid activation
            const confidence = 1 / (1 + Math.exp(-prediction));

            return {
                confidence: confidence,
                prediction: confidence > 0.5 ? 'profane' : 'clean',
                features: features.slice(0, 21) // Return first 21 meaningful features
            };
        } catch (error) {
            console.error('❌ Simple ML prediction error:', error);
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
        const mlResult = this.predictProfanity(text);
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

    // Train the model with sample data (improved gradient descent)
    async trainModel(trainingData) {
        if (!this.isModelLoaded || this.model.trained) {
            return;
        }

        try {
            let learningRate = 0.005; // Reduced learning rate for stability
            const epochs = 200; // Increased epochs for better convergence
            const batchSize = 32; // Batch processing for efficiency

            console.log(`🤖 Training model with ${trainingData.length} examples...`);

            for (let epoch = 0; epoch < epochs; epoch++) {
                let totalLoss = 0;
                let correctPredictions = 0;

                // Shuffle training data for better learning
                const shuffledData = [...trainingData].sort(() => Math.random() - 0.5);

                // Process in batches
                for (let i = 0; i < shuffledData.length; i += batchSize) {
                    const batch = shuffledData.slice(i, i + batchSize);
                    let batchLoss = 0;

                    for (const item of batch) {
                        const features = this.extractFeatures(item.text);
                        const target = item.isProfane ? 1 : 0;

                        // Forward pass
                        let prediction = this.model.bias;
                        for (let j = 0; j < Math.min(features.length, this.model.weights.length); j++) {
                            prediction += features[j] * this.model.weights[j];
                        }

                        // Sigmoid activation
                        const output = 1 / (1 + Math.exp(-prediction));

                        // Calculate loss (binary cross-entropy)
                        const loss = target * Math.log(output + 1e-8) + (1 - target) * Math.log(1 - output + 1e-8);
                        batchLoss += loss;

                        // Count correct predictions
                        if ((output > 0.5 && target === 1) || (output <= 0.5 && target === 0)) {
                            correctPredictions++;
                        }

                        // Backward pass (gradient descent)
                        const error = output - target;

                        // Update bias
                        this.model.bias -= learningRate * error;

                        // Update weights
                        for (let j = 0; j < Math.min(features.length, this.model.weights.length); j++) {
                            this.model.weights[j] -= learningRate * error * features[j];
                        }
                    }

                    totalLoss += batchLoss / batch.length;
                }

                const accuracy = correctPredictions / trainingData.length;
                const avgLoss = totalLoss / Math.ceil(trainingData.length / batchSize);

                // Log progress every 20 epochs
                if (epoch % 20 === 0 || epoch === epochs - 1) {
                    console.log(`Epoch ${epoch}: Loss = ${avgLoss.toFixed(4)}, Accuracy = ${(accuracy * 100).toFixed(2)}%`);
                }

                // Early stopping if accuracy is high enough and loss is low
                if (accuracy > 0.95 && Math.abs(avgLoss) < 0.1) {
                    console.log(`Early stopping at epoch ${epoch} - High accuracy achieved`);
                    break;
                }

                // Learning rate decay
                if (epoch % 50 === 0 && epoch > 0) {
                    learningRate *= 0.9;
                }
            }

            this.model.trained = true;
            await this.saveModel(); // Save the trained model

            console.log('🤖 Enhanced model training completed and saved');
        } catch (error) {
            console.error('❌ Enhanced training error:', error);
        }
    }

    // Lazy initialization - only train if needed
    async ensureModelReady() {
        if (!this.isModelLoaded) {
            await this.initializeModel();
        }

        if (this.isModelLoaded && !this.model.trained) {
            const trainingData = this.generateTrainingData();
            await this.trainModel(trainingData);
        }
    }

    // Generate comprehensive training data
    generateTrainingData() {
        return [
            // Clean examples - Greetings and Polite Language
            { text: "Hello world", isProfane: false },
            { text: "How are you today?", isProfane: false },
            { text: "Good morning everyone", isProfane: false },
            { text: "Thank you for your help", isProfane: false },
            { text: "Have a nice day", isProfane: false },
            { text: "Please and thank you", isProfane: false },
            { text: "Excuse me sir", isProfane: false },
            { text: "I appreciate your time", isProfane: false },
            { text: "Best regards", isProfane: false },
            { text: "Looking forward to hearing from you", isProfane: false },

            // Clean examples - Academic and Professional
            { text: "This is a great project", isProfane: false },
            { text: "I love programming", isProfane: false },
            { text: "The weather is nice", isProfane: false },
            { text: "My name is John", isProfane: false },
            { text: "This is amazing", isProfane: false },
            { text: "Computer science is fascinating", isProfane: false },
            { text: "The algorithm works perfectly", isProfane: false },
            { text: "Database optimization is important", isProfane: false },
            { text: "Machine learning is the future", isProfane: false },
            { text: "Software engineering principles", isProfane: false },

            // Clean examples - Legitimate Names and Places
            { text: "Harshit is a great name", isProfane: false },
            { text: "Christopher is here", isProfane: false },
            { text: "Dickinson is a good school", isProfane: false },
            { text: "Assad is from Syria", isProfane: false },
            { text: "Cockburn is a place in Australia", isProfane: false },
            { text: "Helen is my friend", isProfane: false },
            { text: "My name is Assad", isProfane: false },
            { text: "Dickinson University is great", isProfane: false },
            { text: "Christopher Columbus discovered America", isProfane: false },
            { text: "Helen of Troy was beautiful", isProfane: false },

            // Clean examples - Common Words with Profanity Substrings
            { text: "classic music", isProfane: false },
            { text: "massive project", isProfane: false },
            { text: "assistance program", isProfane: false },
            { text: "assessment tool", isProfane: false },
            { text: "assignment due tomorrow", isProfane: false },
            { text: "assumption is wrong", isProfane: false },
            { text: "assurance policy", isProfane: false },
            { text: "assembly line", isProfane: false },
            { text: "assert your rights", isProfane: false },
            { text: "assess the situation", isProfane: false },
            { text: "assign tasks", isProfane: false },
            { text: "assist with homework", isProfane: false },
            { text: "assume responsibility", isProfane: false },
            { text: "assure quality", isProfane: false },
            { text: "asset management", isProfane: false },

            // Clean examples - Medical and Scientific Terms
            { text: "penicillin is an antibiotic", isProfane: false },
            { text: "testicular cancer treatment", isProfane: false },
            { text: "analgesic medication", isProfane: false },
            { text: "anesthetic procedure", isProfane: false },
            { text: "analytical chemistry", isProfane: false },
            { text: "analytical thinking", isProfane: false },
            { text: "penicillin discovery", isProfane: false },
            { text: "testicular examination", isProfane: false },

            // Clean examples - Contextual Sentences
            { text: "The class is interesting", isProfane: false },
            { text: "Pass the salt please", isProfane: false },
            { text: "Glass of water", isProfane: false },
            { text: "Grass is green", isProfane: false },
            { text: "Mass production", isProfane: false },
            { text: "Classic literature", isProfane: false },
            { text: "Passionate about learning", isProfane: false },
            { text: "Massive improvement", isProfane: false },

            // Profane examples - Direct Profanity
            { text: "fuck you", isProfane: true },
            { text: "fuck this shit", isProfane: true },
            { text: "you fucking idiot", isProfane: true },
            { text: "fucking hell", isProfane: true },
            { text: "fuck off", isProfane: true },
            { text: "fucking amazing", isProfane: true },
            { text: "fuck yeah", isProfane: true },
            { text: "fucking right", isProfane: true },
            { text: "fuck no", isProfane: true },
            { text: "fucking stupid", isProfane: true },

            // Profane examples - Insults and Offensive Language
            { text: "you are a bitch", isProfane: true },
            { text: "you bitch", isProfane: true },
            { text: "stupid bitch", isProfane: true },
            { text: "you are stupid", isProfane: true },
            { text: "you idiot", isProfane: true },
            { text: "stupid moron", isProfane: true },
            { text: "you asshole", isProfane: true },
            { text: "damn it", isProfane: true },
            { text: "damn you", isProfane: true },
            { text: "you damn idiot", isProfane: true },

            // Profane examples - Sexual and Vulgar Language
            { text: "this is shit", isProfane: true },
            { text: "shit head", isProfane: true },
            { text: "bullshit", isProfane: true },
            { text: "holy shit", isProfane: true },
            { text: "shit happens", isProfane: true },
            { text: "you cock", isProfane: true },
            { text: "dick head", isProfane: true },
            { text: "pussy", isProfane: true },
            { text: "cunt", isProfane: true },
            { text: "whore", isProfane: true },
            { text: "slut", isProfane: true },
            { text: "bastard", isProfane: true },

            // Profane examples - Racial and Discriminatory Language
            { text: "nigger", isProfane: true },
            { text: "fag", isProfane: true },
            { text: "retard", isProfane: true },
            { text: "gay ass", isProfane: true },
            { text: "you fag", isProfane: true },
            { text: "stupid retard", isProfane: true },
            { text: "nazi", isProfane: true },
            { text: "hitler", isProfane: true },

            // Profane examples - Threats and Violence
            { text: "kill yourself", isProfane: true },
            { text: "kys", isProfane: true },
            { text: "go die", isProfane: true },
            { text: "I hate you", isProfane: true },
            { text: "you suck", isProfane: true },
            { text: "screw you", isProfane: true },
            { text: "screw this", isProfane: true },
            { text: "screw off", isProfane: true },

            // Profane examples - Contextual Profanity
            { text: "what the hell", isProfane: true },
            { text: "hell no", isProfane: true },
            { text: "hell yeah", isProfane: true },
            { text: "go to hell", isProfane: true },
            { text: "this is fucking amazing", isProfane: true },
            { text: "fucking awesome", isProfane: true },
            { text: "fucking brilliant", isProfane: true },
            { text: "fucking terrible", isProfane: true },
            { text: "fucking ridiculous", isProfane: true },
            { text: "fucking unbelievable", isProfane: true },

            // Profane examples - Internet Slang and Abbreviations
            { text: "wtf", isProfane: true },
            { text: "stfu", isProfane: true },
            { text: "gtfo", isProfane: true },
            { text: "fml", isProfane: true },
            { text: "omfg", isProfane: true },
            { text: "what the fuck", isProfane: true },
            { text: "shut the fuck up", isProfane: true },
            { text: "get the fuck out", isProfane: true },
            { text: "fuck my life", isProfane: true },
            { text: "oh my fucking god", isProfane: true },

            // Profane examples - Mild Profanity and Expressions
            { text: "damn it", isProfane: true },
            { text: "damn you", isProfane: true },
            { text: "damn right", isProfane: true },
            { text: "damn wrong", isProfane: true },
            { text: "damn good", isProfane: true },
            { text: "damn bad", isProfane: true },
            { text: "damn sure", isProfane: true },
            { text: "damn straight", isProfane: true },
            { text: "damn it all", isProfane: true },
            { text: "damn this", isProfane: true },

            // Profane examples - Compound Profanity
            { text: "motherfucker", isProfane: true },
            { text: "son of a bitch", isProfane: true },
            { text: "asshole", isProfane: true },
            { text: "dumbass", isProfane: true },
            { text: "smartass", isProfane: true },
            { text: "badass", isProfane: true },
            { text: "hardass", isProfane: true },
            { text: "jackass", isProfane: true },
            { text: "kiss ass", isProfane: true },
            { text: "kick ass", isProfane: true },

            // Profane examples - Emotional Expressions
            { text: "I'm pissed off", isProfane: true },
            { text: "piss off", isProfane: true },
            { text: "pissed", isProfane: true },
            { text: "pissing me off", isProfane: true },
            { text: "piss poor", isProfane: true },
            { text: "pissed as hell", isProfane: true },
            { text: "pissed off", isProfane: true },
            { text: "pissed away", isProfane: true },

            // Edge cases - Borderline Content
            { text: "this sucks", isProfane: true },
            { text: "you suck", isProfane: true },
            { text: "that sucks", isProfane: true },
            { text: "life sucks", isProfane: true },
            { text: "it sucks", isProfane: true },
            { text: "sucks to be you", isProfane: true },
            { text: "this blows", isProfane: true },
            { text: "you blow", isProfane: true },
            { text: "that blows", isProfane: true },
            { text: "blows chunks", isProfane: true },

            // TARGETED TRAINING: Internet Slang and Abbreviations (Failed Cases)
            { text: "stfu", isProfane: true },
            { text: "gtfo", isProfane: true },
            { text: "fml", isProfane: true },
            { text: "omfg", isProfane: true },
            { text: "kys", isProfane: true },
            { text: "stfu please", isProfane: true },
            { text: "gtfo now", isProfane: true },
            { text: "fml this sucks", isProfane: true },
            { text: "omfg really", isProfane: true },
            { text: "kys loser", isProfane: true },
            { text: "stfu idiot", isProfane: true },
            { text: "gtfo here", isProfane: true },
            { text: "fml why", isProfane: true },
            { text: "omfg no", isProfane: true },
            { text: "kys please", isProfane: true },

            // TARGETED TRAINING: Euphemistic Profanity (Failed Cases)
            { text: "screw you", isProfane: true },
            { text: "screw this", isProfane: true },
            { text: "screw off", isProfane: true },
            { text: "screw that", isProfane: true },
            { text: "screw him", isProfane: true },
            { text: "screw her", isProfane: true },
            { text: "screw it", isProfane: true },
            { text: "screw them", isProfane: true },
            { text: "screw this shit", isProfane: true },
            { text: "screw you too", isProfane: true },
            { text: "screw this place", isProfane: true },
            { text: "screw off man", isProfane: true },
            { text: "screw that idea", isProfane: true },
            { text: "screw him over", isProfane: true },
            { text: "screw her up", isProfane: true },

            // TARGETED TRAINING: Context-Dependent Profanity (Failed Cases)
            { text: "this is fucking amazing", isProfane: true },
            { text: "that's fucking awesome", isProfane: true },
            { text: "fucking brilliant idea", isProfane: true },
            { text: "fucking incredible", isProfane: true },
            { text: "fucking outstanding", isProfane: true },
            { text: "fucking fantastic", isProfane: true },
            { text: "fucking marvelous", isProfane: true },
            { text: "fucking spectacular", isProfane: true },
            { text: "fucking wonderful", isProfane: true },
            { text: "fucking perfect", isProfane: true },
            { text: "fucking excellent", isProfane: true },
            { text: "fucking great", isProfane: true },
            { text: "fucking good", isProfane: true },
            { text: "fucking nice", isProfane: true },
            { text: "fucking cool", isProfane: true },

            // TARGETED TRAINING: Smartass and Similar Terms (Failed Cases)
            { text: "smartass", isProfane: true },
            { text: "you smartass", isProfane: true },
            { text: "smartass comment", isProfane: true },
            { text: "smartass remark", isProfane: true },
            { text: "smartass answer", isProfane: true },
            { text: "smartass response", isProfane: true },
            { text: "smartass attitude", isProfane: true },
            { text: "smartass behavior", isProfane: true },
            { text: "smartass tone", isProfane: true },
            { text: "smartass way", isProfane: true },
            { text: "smartass look", isProfane: true },
            { text: "smartass smile", isProfane: true },
            { text: "smartass grin", isProfane: true },
            { text: "smartass reply", isProfane: true },
            { text: "smartass comeback", isProfane: true },

            // TARGETED TRAINING: More Internet Slang Variations
            { text: "wtf", isProfane: true },
            { text: "wtf is this", isProfane: true },
            { text: "wtf man", isProfane: true },
            { text: "wtf dude", isProfane: true },
            { text: "wtf bro", isProfane: true },
            { text: "wtf happened", isProfane: true },
            { text: "wtf are you doing", isProfane: true },
            { text: "wtf is wrong", isProfane: true },
            { text: "wtf is going on", isProfane: true },
            { text: "wtf is this shit", isProfane: true },
            { text: "wtf is happening", isProfane: true },
            { text: "wtf is the matter", isProfane: true },
            { text: "wtf is the problem", isProfane: true },
            { text: "wtf is the issue", isProfane: true },
            { text: "wtf is the deal", isProfane: true },

            // TARGETED TRAINING: More Euphemistic Variations
            { text: "darn it", isProfane: false },
            { text: "darn you", isProfane: false },
            { text: "darn this", isProfane: false },
            { text: "darn that", isProfane: false },
            { text: "darn him", isProfane: false },
            { text: "darn her", isProfane: false },
            { text: "darn it all", isProfane: false },
            { text: "darn right", isProfane: false },
            { text: "darn good", isProfane: false },
            { text: "darn bad", isProfane: false },
            { text: "darn sure", isProfane: false },
            { text: "darn straight", isProfane: false },
            { text: "darn tootin", isProfane: false },
            { text: "darn skippy", isProfane: false },
            { text: "darn well", isProfane: false },

            // TARGETED TRAINING: More Contextual Profanity Variations
            { text: "fucking hell yeah", isProfane: true },
            { text: "fucking right on", isProfane: true },
            { text: "fucking absolutely", isProfane: true },
            { text: "fucking definitely", isProfane: true },
            { text: "fucking certainly", isProfane: true },
            { text: "fucking totally", isProfane: true },
            { text: "fucking completely", isProfane: true },
            { text: "fucking entirely", isProfane: true },
            { text: "fucking utterly", isProfane: true },
            { text: "fucking extremely", isProfane: true },
            { text: "fucking incredibly", isProfane: true },
            { text: "fucking remarkably", isProfane: true },
            { text: "fucking exceptionally", isProfane: true },
            { text: "fucking extraordinarily", isProfane: true },
            { text: "fucking unbelievably", isProfane: true },

            // TARGETED TRAINING: Context-Dependent Profanity (Positive Context)
            { text: "this is fucking amazing", isProfane: true },
            { text: "that's fucking awesome", isProfane: true },
            { text: "fucking brilliant idea", isProfane: true },
            { text: "fucking incredible work", isProfane: true },
            { text: "fucking outstanding performance", isProfane: true },
            { text: "fucking fantastic job", isProfane: true },
            { text: "fucking marvelous achievement", isProfane: true },
            { text: "fucking spectacular results", isProfane: true },
            { text: "fucking wonderful progress", isProfane: true },
            { text: "fucking perfect solution", isProfane: true },
            { text: "fucking excellent quality", isProfane: true },
            { text: "fucking great success", isProfane: true },
            { text: "fucking good work", isProfane: true },
            { text: "fucking nice improvement", isProfane: true },
            { text: "fucking cool feature", isProfane: true },

            // TARGETED TRAINING: Clean Euphemisms (Should NOT be flagged)
            { text: "darn it", isProfane: false },
            { text: "darn you", isProfane: false },
            { text: "darn this", isProfane: false },
            { text: "darn that", isProfane: false },
            { text: "darn him", isProfane: false },
            { text: "darn her", isProfane: false },
            { text: "darn it all", isProfane: false },
            { text: "darn right", isProfane: false },
            { text: "darn good", isProfane: false },
            { text: "darn bad", isProfane: false },
            { text: "darn sure", isProfane: false },
            { text: "darn straight", isProfane: false },
            { text: "darn tootin", isProfane: false },
            { text: "darn skippy", isProfane: false },
            { text: "darn well", isProfane: false },
            { text: "gosh darn", isProfane: false },
            { text: "gosh darn it", isProfane: false },
            { text: "heck yeah", isProfane: false },
            { text: "heck no", isProfane: false },
            { text: "heck of a", isProfane: false },
            { text: "shoot dang", isProfane: false },
            { text: "shoot fire", isProfane: false },
            { text: "drat it", isProfane: false },
            { text: "blimey mate", isProfane: false },

            // TARGETED TRAINING: Legitimate Compound Words (Should NOT be flagged)
            { text: "classic music", isProfane: false },
            { text: "classic literature", isProfane: false },
            { text: "classic art", isProfane: false },
            { text: "classic design", isProfane: false },
            { text: "classic style", isProfane: false },
            { text: "massive project", isProfane: false },
            { text: "massive success", isProfane: false },
            { text: "massive improvement", isProfane: false },
            { text: "massive achievement", isProfane: false },
            { text: "massive effort", isProfane: false },
            { text: "passionate love", isProfane: false },
            { text: "passionate speech", isProfane: false },
            { text: "passionate work", isProfane: false },
            { text: "passionate dedication", isProfane: false },
            { text: "passionate commitment", isProfane: false },
            { text: "assistance program", isProfane: false },
            { text: "assistance center", isProfane: false },
            { text: "assistance fund", isProfane: false },
            { text: "assistance service", isProfane: false },
            { text: "assistance office", isProfane: false },
            { text: "assessment tool", isProfane: false },
            { text: "assessment method", isProfane: false },
            { text: "assessment process", isProfane: false },
            { text: "assessment criteria", isProfane: false },
            { text: "assessment report", isProfane: false },
            { text: "assertion statement", isProfane: false },
            { text: "assertion claim", isProfane: false },
            { text: "assertion proof", isProfane: false },
            { text: "assertion evidence", isProfane: false },
            { text: "assertion argument", isProfane: false },
            { text: "assignment project", isProfane: false },
            { text: "assignment task", isProfane: false },
            { text: "assignment work", isProfane: false },
            { text: "assignment due", isProfane: false },
            { text: "assignment grade", isProfane: false },
            { text: "assumption theory", isProfane: false },
            { text: "assumption basis", isProfane: false },
            { text: "assumption foundation", isProfane: false },
            { text: "assumption principle", isProfane: false },
            { text: "assumption concept", isProfane: false },
            { text: "assurance policy", isProfane: false },
            { text: "assurance guarantee", isProfane: false },
            { text: "assurance promise", isProfane: false },
            { text: "assurance commitment", isProfane: false },
            { text: "assurance security", isProfane: false },
            { text: "penicillin antibiotic", isProfane: false },
            { text: "penicillin treatment", isProfane: false },
            { text: "penicillin medication", isProfane: false },
            { text: "penicillin drug", isProfane: false },
            { text: "penicillin therapy", isProfane: false },
            { text: "analytical thinking", isProfane: false },
            { text: "analytical approach", isProfane: false },
            { text: "analytical method", isProfane: false },
            { text: "analytical process", isProfane: false },
            { text: "analytical skills", isProfane: false },

            // UPLOAD ENDPOINT TARGETED TRAINING: Academic/Technical Context
            { text: "classic music notes", isProfane: false },
            { text: "classic literature notes", isProfane: false },
            { text: "classic art notes", isProfane: false },
            { text: "classic philosophy notes", isProfane: false },
            { text: "classic history notes", isProfane: false },
            { text: "massive project pdf", isProfane: false },
            { text: "massive database project", isProfane: false },
            { text: "massive research project", isProfane: false },
            { text: "massive engineering project", isProfane: false },
            { text: "massive data analysis", isProfane: false },
            { text: "assistance program notes", isProfane: false },
            { text: "assistance program guide", isProfane: false },
            { text: "assistance program manual", isProfane: false },
            { text: "assistance program handbook", isProfane: false },
            { text: "assistance program documentation", isProfane: false },
            { text: "penicillin notes medical", isProfane: false },
            { text: "penicillin research notes", isProfane: false },
            { text: "penicillin study notes", isProfane: false },
            { text: "penicillin pharmacology notes", isProfane: false },
            { text: "penicillin microbiology notes", isProfane: false },
            { text: "analytical thinking process", isProfane: false },
            { text: "analytical thinking skills", isProfane: false },
            { text: "analytical thinking methodology", isProfane: false },
            { text: "analytical thinking framework", isProfane: false },
            { text: "analytical thinking approach", isProfane: false },

            // UPLOAD ENDPOINT TARGETED TRAINING: Numerical Context (Years, Dates)
            { text: "2024", isProfane: false },
            { text: "2023", isProfane: false },
            { text: "2022", isProfane: false },
            { text: "2021", isProfane: false },
            { text: "2025", isProfane: false },
            { text: "2020", isProfane: false },
            { text: "2019", isProfane: false },
            { text: "2018", isProfane: false },
            { text: "2017", isProfane: false },
            { text: "2016", isProfane: false },
            { text: "Spring 2024", isProfane: false },
            { text: "Fall 2023", isProfane: false },
            { text: "Summer 2024", isProfane: false },
            { text: "Winter 2024", isProfane: false },

            // UPLOAD ENDPOINT TARGETED TRAINING: Positive Context Profanity (Should be flagged)
            { text: "this is fucking awesome content", isProfane: true },
            { text: "fucking awesome assignment", isProfane: true },
            { text: "fucking great homework", isProfane: true },
            { text: "fucking amazing project", isProfane: true },
            { text: "fucking brilliant solution", isProfane: true },
            { text: "fucking incredible work", isProfane: true },
            { text: "fucking outstanding performance", isProfane: true },
            { text: "fucking fantastic job", isProfane: true },
            { text: "fucking marvelous achievement", isProfane: true },
            { text: "fucking spectacular results", isProfane: true },
            { text: "fucking wonderful progress", isProfane: true },
            { text: "fucking perfect solution", isProfane: true },
            { text: "fucking excellent quality", isProfane: true },
            { text: "fucking great success", isProfane: true },
            { text: "fucking good work", isProfane: true },
            { text: "fucking nice improvement", isProfane: true },
            { text: "fucking cool feature", isProfane: true },

            // UPLOAD ENDPOINT TARGETED TRAINING: Academic Categories (Should NOT be flagged)
            { text: "Homework", isProfane: false },
            { text: "Assignment", isProfane: false },
            { text: "Project", isProfane: false },
            { text: "Research", isProfane: false },
            { text: "Study Guide", isProfane: false },
            { text: "Lecture Notes", isProfane: false },
            { text: "Lab Report", isProfane: false },
            { text: "Exam Review", isProfane: false },
            { text: "Practice Problems", isProfane: false },
            { text: "Syllabus", isProfane: false },
            { text: "Course Material", isProfane: false },
            { text: "Reading List", isProfane: false },
            { text: "Reference", isProfane: false },
            { text: "Textbook", isProfane: false },
            { text: "Supplemental", isProfane: false },

            // UPLOAD ENDPOINT TARGETED TRAINING: File Naming Patterns (Should NOT be flagged)
            { text: "classic_music_notes", isProfane: false },
            { text: "massive_project.pdf", isProfane: false },
            { text: "assistance_program", isProfane: false },
            { text: "penicillin_notes", isProfane: false },
            { text: "analytical_thinking", isProfane: false },
            { text: "classic_literature_notes", isProfane: false },
            { text: "massive_database_project", isProfane: false },
            { text: "assistance_program_guide", isProfane: false },
            { text: "penicillin_research_notes", isProfane: false },
            { text: "analytical_thinking_process", isProfane: false },
            { text: "computer_science_notes", isProfane: false },
            { text: "mathematics_homework", isProfane: false },
            { text: "physics_lab_report", isProfane: false },
            { text: "chemistry_experiment", isProfane: false },
            { text: "biology_research", isProfane: false },
            { text: "engineering_project", isProfane: false },
            { text: "business_case_study", isProfane: false },
            { text: "economics_assignment", isProfane: false },
            { text: "history_research_paper", isProfane: false },
            { text: "psychology_experiment", isProfane: false },
            { text: "philosophy_essay", isProfane: false },
            { text: "art_history_notes", isProfane: false },
            { text: "music_theory_assignment", isProfane: false },
            { text: "drama_script_analysis", isProfane: false },
            { text: "literature_analysis", isProfane: false },

            // UPLOAD ENDPOINT TARGETED TRAINING: File Extensions (Should NOT be flagged)
            { text: "notes.pdf", isProfane: false },
            { text: "assignment.docx", isProfane: false },
            { text: "project.pptx", isProfane: false },
            { text: "research.xlsx", isProfane: false },
            { text: "homework.txt", isProfane: false },
            { text: "exam_prep.zip", isProfane: false },
            { text: "study_guide.pdf", isProfane: false },
            { text: "lab_report.docx", isProfane: false },
            { text: "presentation.pptx", isProfane: false },
            { text: "data_analysis.xlsx", isProfane: false },

            // UPLOAD ENDPOINT TARGETED TRAINING: Enhanced Positive Context Profanity (Should be flagged)
            { text: "this is fucking awesome content", isProfane: true },
            { text: "fucking awesome assignment", isProfane: true },
            { text: "fucking great homework", isProfane: true },
            { text: "fucking amazing project", isProfane: true },
            { text: "fucking brilliant solution", isProfane: true },
            { text: "fucking incredible work", isProfane: true },
            { text: "fucking outstanding performance", isProfane: true },
            { text: "fucking fantastic job", isProfane: true },
            { text: "fucking marvelous achievement", isProfane: true },
            { text: "fucking spectacular results", isProfane: true },
            { text: "fucking wonderful progress", isProfane: true },
            { text: "fucking perfect solution", isProfane: true },
            { text: "fucking excellent quality", isProfane: true },
            { text: "fucking great success", isProfane: true },
            { text: "fucking good work", isProfane: true },
            { text: "fucking nice improvement", isProfane: true },
            { text: "fucking cool feature", isProfane: true },
            { text: "this assignment is fucking amazing", isProfane: true },
            { text: "this project is fucking awesome", isProfane: true },
            { text: "this homework is fucking great", isProfane: true },
            { text: "this research is fucking brilliant", isProfane: true },
            { text: "this analysis is fucking incredible", isProfane: true },
            { text: "this work is fucking outstanding", isProfane: true },
            { text: "this performance is fucking fantastic", isProfane: true },
            { text: "this achievement is fucking marvelous", isProfane: true },
            { text: "this result is fucking spectacular", isProfane: true },
            { text: "this progress is fucking wonderful", isProfane: true },
            { text: "this solution is fucking perfect", isProfane: true },
            { text: "this quality is fucking excellent", isProfane: true },
            { text: "this success is fucking great", isProfane: true },
            { text: "this work is fucking good", isProfane: true },
            { text: "this improvement is fucking nice", isProfane: true },
            { text: "this feature is fucking cool", isProfane: true },

            // CRITICAL PUBLIC-FACING ENDPOINTS: Heavy Focus on Usernames & File Uploads
            // Registration Endpoint Training - HEAVILY WEIGHTED (Public-Facing)
            { text: "fuckuser123", isProfane: true },
            { text: "fuckuser", isProfane: true },
            { text: "shituser", isProfane: true },
            { text: "damnuser", isProfane: true },
            { text: "bitchuser", isProfane: true },
            { text: "assuser", isProfane: true },
            { text: "dickuser", isProfane: true },
            { text: "cockuser", isProfane: true },
            { text: "pussyuser", isProfane: true },
            { text: "cuntuser", isProfane: true },
            { text: "fuckhead", isProfane: true },
            { text: "shithead", isProfane: true },
            { text: "damnhead", isProfane: true },
            { text: "bitchhead", isProfane: true },
            { text: "asshead", isProfane: true },
            { text: "dickhead", isProfane: true },
            { text: "cockhead", isProfane: true },
            { text: "pussyhead", isProfane: true },
            { text: "cunthead", isProfane: true },
            { text: "whoreuser", isProfane: true },
            { text: "slutuser", isProfane: true },
            { text: "bastarduser", isProfane: true },
            { text: "motherfuckeruser", isProfane: true },
            { text: "normaluser", isProfane: false },
            { text: "studentuser", isProfane: false },
            { text: "johnuser", isProfane: false },
            { text: "maryuser", isProfane: false },
            { text: "alexuser", isProfane: false },
            { text: "sarahuser", isProfane: false },
            { text: "mikeuser", isProfane: false },
            { text: "emilyuser", isProfane: false },
            { text: "daviduser", isProfane: false },
            { text: "lisauser", isProfane: false },
            { text: "chrisuser", isProfane: false },
            { text: "jessuser", isProfane: false },
            { text: "bitchy_user", isProfane: true },
            { text: "damn_lastname", isProfane: true },
            { text: "fuck_firstname", isProfane: true },
            { text: "shit_lastname", isProfane: true },
            { text: "ass_firstname", isProfane: true },
            { text: "dick_lastname", isProfane: true },
            { text: "cock_firstname", isProfane: true },
            { text: "pussy_lastname", isProfane: true },
            { text: "cunt_firstname", isProfane: true },
            { text: "whore_lastname", isProfane: true },
            { text: "slut_firstname", isProfane: true },
            { text: "bastard_lastname", isProfane: true },
            { text: "motherfucker_firstname", isProfane: true },
            { text: "normal_firstname", isProfane: false },
            { text: "john_lastname", isProfane: false },
            { text: "mary_firstname", isProfane: false },
            { text: "alex_lastname", isProfane: false },
            { text: "sarah_firstname", isProfane: false },
            { text: "mike_lastname", isProfane: false },
            { text: "emily_firstname", isProfane: false },
            { text: "david_lastname", isProfane: false },
            { text: "lisa_firstname", isProfane: false },
            { text: "chris_lastname", isProfane: false },
            { text: "jess_firstname", isProfane: false },
            { text: "a$$hole", isProfane: true },
            { text: "f*ckuser", isProfane: true },
            { text: "sh1thead", isProfane: true },
            { text: "a$$user", isProfane: true },
            { text: "f*ckhead", isProfane: true },
            { text: "sh1tuser", isProfane: true },
            { text: "d@mnuser", isProfane: true },
            { text: "b1tchuser", isProfane: true },
            { text: "a$$head", isProfane: true },
            { text: "d1ckuser", isProfane: true },
            { text: "c0ckuser", isProfane: true },
            { text: "p@ssyuser", isProfane: true },
            { text: "c@ntuser", isProfane: true },
            { text: "wh0reuser", isProfane: true },
            { text: "sl@tuser", isProfane: true },
            { text: "b@starduser", isProfane: true },
            { text: "normaluser", isProfane: false },
            { text: "studentuser", isProfane: false },
            { text: "johnuser", isProfane: false },
            { text: "maryuser", isProfane: false },
            { text: "alexuser", isProfane: false },
            { text: "sarahuser", isProfane: false },
            { text: "mikeuser", isProfane: false },
            { text: "emilyuser", isProfane: false },
            { text: "daviduser", isProfane: false },
            { text: "lisauser", isProfane: false },
            { text: "chrisuser", isProfane: false },
            { text: "jessuser", isProfane: false },

            // File Upload Endpoint Training - HEAVILY WEIGHTED (Public-Facing)
            { text: "fucking_notes.pdf", isProfane: true },
            { text: "shitty_homework.docx", isProfane: true },
            { text: "damn_assignment.pptx", isProfane: true },
            { text: "bitchy_project.xlsx", isProfane: true },
            { text: "asshole_lab_report.txt", isProfane: true },
            { text: "dickhead_research.zip", isProfane: true },
            { text: "cocky_analysis.pdf", isProfane: true },
            { text: "pussy_notes.docx", isProfane: true },
            { text: "cunt_homework.pptx", isProfane: true },
            { text: "whore_assignment.xlsx", isProfane: true },
            { text: "slutty_project.txt", isProfane: true },
            { text: "bastard_lab_report.zip", isProfane: true },
            { text: "motherfucker_research.pdf", isProfane: true },
            { text: "fuck_this_assignment.pdf", isProfane: true },
            { text: "shit_homework.docx", isProfane: true },
            { text: "damn_project.pptx", isProfane: true },
            { text: "bitch_lab_report.xlsx", isProfane: true },
            { text: "ass_notes.txt", isProfane: true },
            { text: "dick_research.zip", isProfane: true },
            { text: "cock_analysis.pdf", isProfane: true },
            { text: "pussy_assignment.docx", isProfane: true },
            { text: "cunt_project.pptx", isProfane: true },
            { text: "whore_homework.xlsx", isProfane: true },
            { text: "slut_notes.txt", isProfane: true },
            { text: "bastard_lab_report.zip", isProfane: true },
            { text: "classic_manna_notes.pdf", isProfane: false },
            { text: "massive_project.docx", isProfane: false },
            { text: "assistance_program.pptx", isProfane: false },
            { text: "penicillin_notes.xlsx", isProfane: false },
            { text: "analytical_thinking.txt", isProfane: false },
            { text: "computer_science_notes.zip", isProfane: false },
            { text: "mathematics_homework.pdf", isProfane: false },
            { text: "physics_lab_report.docx", isProfane: false },
            { text: "chemistry_experiment.pptx", isProfane: false },
            { text: "biology_research.xlsx", isProfane: false },
            { text: "engineering_project.txt", isProfane: false },
            { text: "statistics_analysis.pdf", isProfane: false },
            { text: "calculus_homework.docx", isProfane: false },
            { text: "linear_algebra_notes.pptx", isProfane: false },
            { text: "discrete_math_problems.xlsx", isProfane: false },
            { text: "data_structures_implementation.txt", isProfane: false },
            { text: "algorithms_analysis.zip", isProfane: false },
            { text: "database_design.pdf", isProfane: false },
            { text: "software_engineering_project.docx", isProfane: false },
            { text: "machine_learning_notes.pptx", isProfane: false },
            { text: "artificial_intelligence_research.xlsx", isProfane: false },
            { text: "cybersecurity_analysis.txt", isProfane: false },
            { text: "network_protocols_study.zip", isProfane: false },
            { text: "operating_systems_concepts.pdf", isProfane: false },
            { text: "computer_graphics_project.docx", isProfane: false },
            { text: "web_development_notes.pptx", isProfane: false },
            { text: "mobile_app_development.xlsx", isProfane: false },
            { text: "game_design_documentation.txt", isProfane: false },
            { text: "user_interface_design.zip", isProfane: false },

            // ADMIN-FACING ENDPOINTS: Minimal Training (Less Critical)
            // Report Endpoint Training - Reduced
            { text: "fucking_inappropriate.pdf", isProfane: true },
            { text: "shitty_content.docx", isProfane: true },
            { text: "This file is fucking inappropriate", isProfane: true },
            { text: "This file contains shitty content", isProfane: true },
            { text: "File contains copyrighted material", isProfane: false },
            { text: "File contains inappropriate content", isProfane: false },

            // Contact Endpoint Training - Reduced
            { text: "Fucking User", isProfane: true },
            { text: "Shitty Problem", isProfane: true },
            { text: "John Doe", isProfane: false },
            { text: "Technical Issue", isProfane: false },
            { text: "This is a fucking great platform", isProfane: true },
            { text: "Thank you for this amazing platform", isProfane: false },

            // Ban User Endpoint Training - Reduced
            { text: "User is a fucking asshole", isProfane: true },
            { text: "User is a shitty person", isProfane: true },
            { text: "Violation of terms of service", isProfane: false },
            { text: "Inappropriate behavior", isProfane: false }
        ];
    }
}

module.exports = SimpleAIProfanityFilter;
