// Enhanced Rule-Based Profanity Filter
// Addresses critical gaps in current system

function enhancedRuleBasedDetection(text) {
    if (!text || typeof text !== 'string') {
        return { found: false, entry: null };
    }

    const originalText = text;
    const lowerText = text.toLowerCase();

    // 1. DIRECT PROFANITY DETECTION (Enhanced)
    const directProfanity = [
        'fuck', 'shit', 'damn', 'bitch', 'ass', 'dick', 'cock', 'pussy', 'cunt',
        'whore', 'slut', 'bastard', 'motherfucker', 'asshole', 'dickhead', 'cocky',
        'fucking', 'shitting', 'damning', 'bitching', 'asshole', 'dickhead', 'cocky',
        'pussied', 'cunted', 'whoring', 'slutting', 'bastarding'
    ];

    // Check for direct profanity with word boundaries
    for (const word of directProfanity) {
        const regex = new RegExp(`\\b${word}\\b`, 'i');
        if (regex.test(lowerText)) {
            // Check if it's a legitimate word
            if (!isLegitimateWord(lowerText, word)) {
                return {
                    found: true,
                    entry: {
                        id: 'direct-profanity',
                        match: word,
                        severity: 3,
                        tags: ['direct', 'profanity'],
                        method: 'enhanced-rule-based'
                    }
                };
            }
        }
    }

    // 2. SYMBOL SUBSTITUTION DETECTION (New)
    const symbolSubstitutions = [
        { pattern: /f\*ck|f\*\*k|f\$\$k|f#ck|f@ck/i, word: 'fuck' },
        { pattern: /sh\*t|sh\*\*t|sh\$\$t|sh#t|sh@t/i, word: 'shit' },
        { pattern: /d\*mn|d\*\*n|d\$\$n|d#mn|d@mn/i, word: 'damn' },
        { pattern: /b\*tch|b\*\*ch|b\$\$ch|b#tch|b@tch/i, word: 'bitch' },
        { pattern: /a\$\$|a\*\*|a##|a@@|a\$\$hole|a\*\*hole/i, word: 'ass' },
        { pattern: /d\*ck|d\*\*k|d\$\$k|d#ck|d@ck/i, word: 'dick' },
        { pattern: /c\*ck|c\*\*k|c\$\$k|c#ck|c@ck/i, word: 'cock' },
        { pattern: /p\*ssy|p\*\*sy|p\$\$sy|p#ssy|p@ssy/i, word: 'pussy' },
        { pattern: /c\*nt|c\*\*t|c\$\$t|c#nt|c@nt/i, word: 'cunt' },
        { pattern: /wh\*re|wh\*\*e|wh\$\$e|wh#re|wh@re/i, word: 'whore' },
        { pattern: /sl\*t|sl\*\*t|sl\$\$t|sl#t|sl@t/i, word: 'slut' }
    ];

    for (const sub of symbolSubstitutions) {
        if (sub.pattern.test(lowerText)) {
            return {
                found: true,
                entry: {
                    id: 'symbol-substitution',
                    match: sub.word,
                    severity: 3,
                    tags: ['symbol-substitution', 'profanity'],
                    method: 'enhanced-rule-based'
                }
            };
        }
    }

    // 3. NUMBER SUBSTITUTION DETECTION (New)
    const numberSubstitutions = [
        { pattern: /f0ck|f00k|f4ck|f1ck/i, word: 'fuck' },
        { pattern: /sh1t|sh00t|sh4t/i, word: 'shit' },
        { pattern: /d4mn|d1mn|d0mn/i, word: 'damn' },
        { pattern: /b1tch|b4tch|b0tch/i, word: 'bitch' },
        { pattern: /a55|a44|a11/i, word: 'ass' },
        { pattern: /d1ck|d0ck|d4ck/i, word: 'dick' },
        { pattern: /c0ck|c1ck|c4ck/i, word: 'cock' },
        { pattern: /p4ssy|p1ssy|p0ssy/i, word: 'pussy' },
        { pattern: /c4nt|c1nt|c0nt/i, word: 'cunt' },
        { pattern: /wh0re|wh1re|wh4re/i, word: 'whore' },
        { pattern: /sl4t|sl1t|sl0t/i, word: 'slut' }
    ];

    for (const sub of numberSubstitutions) {
        if (sub.pattern.test(lowerText)) {
            return {
                found: true,
                entry: {
                    id: 'number-substitution',
                    match: sub.word,
                    severity: 3,
                    tags: ['number-substitution', 'profanity'],
                    method: 'enhanced-rule-based'
                }
            };
        }
    }

    // 4. CHARACTER SUBSTITUTION DETECTION (New)
    const characterSubstitutions = [
        { pattern: /f@ck|f#ck|f!ck/i, word: 'fuck' },
        { pattern: /sh!t|sh#t|sh@t/i, word: 'shit' },
        { pattern: /d@mn|d#mn|d!mn/i, word: 'damn' },
        { pattern: /b!tch|b#tch|b@tch/i, word: 'bitch' },
        { pattern: /@ss|#ss|!ss/i, word: 'ass' },
        { pattern: /d!ck|d#ck|d@ck/i, word: 'dick' },
        { pattern: /c@ck|c#ck|c!ck/i, word: 'cock' },
        { pattern: /p@ssy|p#ssy|p!ssy/i, word: 'pussy' },
        { pattern: /c@nt|c#nt|c!nt/i, word: 'cunt' },
        { pattern: /wh@re|wh#re|wh!re/i, word: 'whore' },
        { pattern: /sl@t|sl#t|sl!t/i, word: 'slut' }
    ];

    for (const sub of characterSubstitutions) {
        if (sub.pattern.test(lowerText)) {
            return {
                found: true,
                entry: {
                    id: 'character-substitution',
                    match: sub.word,
                    severity: 3,
                    tags: ['character-substitution', 'profanity'],
                    method: 'enhanced-rule-based'
                }
            };
        }
    }

    // 5. COMPOUND WORD DETECTION (New)
    const compoundWords = [
        'fuckuser', 'shituser', 'damnuser', 'bitchuser', 'assuser', 'dickuser',
        'cockuser', 'pussyuser', 'cuntuser', 'whoreuser', 'slutuser', 'bastarduser',
        'fuckhead', 'shithead', 'damnhead', 'bitchhead', 'asshead', 'dickhead',
        'cockhead', 'pussyhead', 'cunthead', 'whorehead', 'sluthead', 'bastardhead',
        'fuckface', 'shitface', 'damnface', 'bitchface', 'assface', 'dickface',
        'cockface', 'pussyface', 'cuntface', 'whoreface', 'slutface', 'bastardface'
    ];

    for (const word of compoundWords) {
        const regex = new RegExp(`\\b${word}\\b`, 'i');
        if (regex.test(lowerText)) {
            return {
                found: true,
                entry: {
                    id: 'compound-word',
                    match: word,
                    severity: 3,
                    tags: ['compound-word', 'profanity'],
                    method: 'enhanced-rule-based'
                }
            };
        }
    }

    // 6. LEET SPEAK DETECTION (New)
    const leetSpeak = [
        { pattern: /fuk|fuq|fuc/i, word: 'fuck' },
        { pattern: /sh1t|sh1t|sh1t/i, word: 'shit' },
        { pattern: /damn|damn|damn/i, word: 'damn' },
        { pattern: /b1tch|b1tch|b1tch/i, word: 'bitch' },
        { pattern: /ass|ass|ass/i, word: 'ass' },
        { pattern: /d1ck|d1ck|d1ck/i, word: 'dick' },
        { pattern: /c0ck|c0ck|c0ck/i, word: 'cock' },
        { pattern: /pussy|pussy|pussy/i, word: 'pussy' },
        { pattern: /cunt|cunt|cunt/i, word: 'cunt' },
        { pattern: /wh0re|wh0re|wh0re/i, word: 'whore' },
        { pattern: /slut|slut|slut/i, word: 'slut' }
    ];

    for (const leet of leetSpeak) {
        if (leet.pattern.test(lowerText)) {
            return {
                found: true,
                entry: {
                    id: 'leet-speak',
                    match: leet.word,
                    severity: 3,
                    tags: ['leet-speak', 'profanity'],
                    method: 'enhanced-rule-based'
                }
            };
        }
    }

    // 7. REPEATED CHARACTER DETECTION (New)
    const repeatedPatterns = [
        { pattern: /f+u+c+k+/i, word: 'fuck' },
        { pattern: /s+h+i+t+/i, word: 'shit' },
        { pattern: /d+a+m+n+/i, word: 'damn' },
        { pattern: /b+i+t+c+h+/i, word: 'bitch' },
        { pattern: /a+s+s+/i, word: 'ass' },
        { pattern: /d+i+c+k+/i, word: 'dick' },
        { pattern: /c+o+c+k+/i, word: 'cock' },
        { pattern: /p+u+s+s+y+/i, word: 'pussy' },
        { pattern: /c+u+n+t+/i, word: 'cunt' },
        { pattern: /w+h+o+r+e+/i, word: 'whore' },
        { pattern: /s+l+u+t+/i, word: 'slut' }
    ];

    for (const repeat of repeatedPatterns) {
        if (repeat.pattern.test(lowerText)) {
            return {
                found: true,
                entry: {
                    id: 'repeated-characters',
                    match: repeat.word,
                    severity: 3,
                    tags: ['repeated-characters', 'profanity'],
                    method: 'enhanced-rule-based'
                }
            };
        }
    }

    // 8. CONTEXTUAL PROFANITY DETECTION (Enhanced)
    const contextualPatterns = [
        { pattern: /you.*fuck|fuck.*you/i, word: 'fuck' },
        { pattern: /this.*shit|shit.*this/i, word: 'shit' },
        { pattern: /what.*damn|damn.*what/i, word: 'damn' },
        { pattern: /stupid.*bitch|bitch.*stupid/i, word: 'bitch' },
        { pattern: /you.*asshole|asshole.*you/i, word: 'asshole' },
        { pattern: /you.*dick|dick.*you/i, word: 'dick' },
        { pattern: /you.*cock|cock.*you/i, word: 'cock' },
        { pattern: /you.*pussy|pussy.*you/i, word: 'pussy' },
        { pattern: /you.*cunt|cunt.*you/i, word: 'cunt' },
        { pattern: /you.*whore|whore.*you/i, word: 'whore' },
        { pattern: /you.*slut|slut.*you/i, word: 'slut' }
    ];

    for (const context of contextualPatterns) {
        if (context.pattern.test(lowerText)) {
            return {
                found: true,
                entry: {
                    id: 'contextual-profanity',
                    match: context.word,
                    severity: 3,
                    tags: ['contextual', 'profanity'],
                    method: 'enhanced-rule-based'
                }
            };
        }
    }

    return { found: false, entry: null };
}

// Helper function to check if a word is legitimate
function isLegitimateWord(text, profaneWord) {
    const legitimateWords = new Set([
        'harshit', 'assad', 'dickinson', 'cockburn', 'butt', 'christopher', 'helen',
        'dickens', 'assassin', 'classic', 'massive', 'passionate', 'assistance',
        'assessment', 'assertion', 'assignment', 'assumption', 'assurance',
        'dickinson', 'cockburn', 'assam', 'christchurch', 'helena',
        'penicillin', 'analytical', 'passion', 'passing', 'passive', 'pasture',
        'assembly', 'assert', 'assess', 'assign', 'assist', 'assume', 'assure', 'asset',
        'music', 'literature', 'project', 'program', 'notes', 'thinking', 'research',
        'homework', 'assignment', 'analysis', 'study', 'lecture', 'lab', 'exam'
    ]);

    // Check if the profane word appears in a legitimate context
    const words = text.toLowerCase().split(/\s+/);
    for (const word of words) {
        if (legitimateWords.has(word)) {
            return true;
        }
    }

    // Check for legitimate compound words
    const legitimateCompounds = [
        'classic music', 'massive project', 'assistance program', 'penicillin notes',
        'analytical thinking', 'computer science', 'mathematics homework', 'physics lab',
        'chemistry experiment', 'biology research', 'engineering project'
    ];

    for (const compound of legitimateCompounds) {
        if (text.toLowerCase().includes(compound)) {
            return true;
        }
    }

    return false;
}

module.exports = { enhancedRuleBasedDetection, isLegitimateWord };
