#!/usr/bin/env node

/**
 * UMD.io Data Cache Script
 * Downloads and caches courses and recent professor data
 */

const fs = require('fs').promises;
const path = require('path');
const https = require('https');

// Configuration
const config = {
    baseUrl: 'https://api.umd.io/v1',
    years: 4, // Cache last 4 years of data
    semesters: ['01', '05', '08', '12'], // Spring, Summer, Fall, Winter
    retryAttempts: 3,
    retryDelay: 1000
};

async function fetchUMDData(endpoint) {
    const url = `${config.baseUrl}${endpoint}`;

    for (let attempt = 1; attempt <= config.retryAttempts; attempt++) {
        try {
            const response = await new Promise((resolve, reject) => {
                https.get(url, (res) => {
                    let data = '';
                    res.on('data', chunk => data += chunk);
                    res.on('end', () => {
                        if (res.statusCode === 200) {
                            resolve(JSON.parse(data));
                        } else {
                            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                        }
                    });
                }).on('error', reject);
            });

            return response;
        } catch (error) {
            console.warn(`⚠️  Attempt ${attempt} failed for ${endpoint}: ${error.message}`);
            if (attempt === config.retryAttempts) {
                throw error;
            }
            await new Promise(resolve => setTimeout(resolve, config.retryDelay * attempt));
        }
    }
}

async function generateSemesters() {
    const semesters = [];
    const currentYear = new Date().getFullYear();

    for (let year = currentYear - config.years; year <= currentYear; year++) {
        for (const semesterCode of config.semesters) {
            const semesterId = `${year}${semesterCode}`;
            semesters.push(semesterId);
        }
    }

    return semesters;
}

async function cacheCourses() {
    console.log('📚 Caching courses...');

    try {
        // Use the lighter /courses/list endpoint instead of full /courses
        const courses = await fetchUMDData('/courses/list?per_page=100');

        const cacheData = {
            timestamp: new Date().toISOString(),
            courses: courses.map(course => ({
                course_id: course.course_id,
                name: course.name
            }))
        };

        await fs.writeFile(
            path.join(__dirname, '..', 'data', 'courses-cache.json'),
            JSON.stringify(cacheData, null, 2)
        );

        console.log(`✅ Cached ${courses.length} courses`);
        return courses.length;
    } catch (error) {
        console.error('❌ Failed to cache courses:', error.message);
        return 0;
    }
}

async function cacheProfessors() {
    console.log('👨‍🏫 Extracting professors using course-specific API calls...');

    try {
        // Load cached courses data
        const coursesData = await fs.readFile(
            path.join(__dirname, '..', 'data', 'courses-cache.json'),
            'utf8'
        );
        const courses = JSON.parse(coursesData);

        if (!courses.courses || courses.courses.length === 0) {
            console.warn('⚠️  No courses data available for professor extraction');
            return 0;
        }

        console.log(`📚 Processing ${courses.courses.length} courses for professor data...`);

        const professorMap = new Map(); // name -> {name, semesters: []}
        const currentYear = new Date().getFullYear();
        const cutoffYear = currentYear - config.years;

        // Process courses in batches
        const batchSize = 50; // Larger batches for efficiency
        let processedCourses = 0;

        for (let i = 0; i < courses.courses.length; i += batchSize) {
            const batch = courses.courses.slice(i, i + batchSize);
            console.log(`📊 Processing courses ${i + 1}-${Math.min(i + batchSize, courses.courses.length)}/${courses.courses.length}`);

            // Process each course in parallel within the batch
            const promises = batch.map(async (course) => {
                try {
                    // Use the efficient course-specific professors endpoint
                    const professors = await fetchUMDData(`/professors?course_id=${course.course_id}`);

                    if (Array.isArray(professors)) {
                        for (const prof of professors) {
                            if (prof.name && prof.taught && Array.isArray(prof.taught)) {
                                const name = prof.name.trim();

                                if (!professorMap.has(name)) {
                                    professorMap.set(name, {
                                        name: name,
                                        semesters: []
                                    });
                                }

                                const professor = professorMap.get(name);

                                // Process taught courses, filter to recent years
                                for (const taught of prof.taught) {
                                    if (taught.semester && taught.course_id) {
                                        const semesterId = taught.semester.toString();
                                        const year = parseInt(semesterId.substring(0, 4));

                                        // Only include recent semesters
                                        if (year >= cutoffYear) {
                                            const semesterNum = semesterId.substring(4, 6);
                                            const semesterName = {
                                                '01': 'Spring', '05': 'Summer', '08': 'Fall', '12': 'Winter'
                                            }[semesterNum];

                                            // Add semester if not already present
                                            const semesterExists = professor.semesters.some(s =>
                                                s.semester === semesterName && s.year === year && s.course_id === taught.course_id
                                            );

                                            if (!semesterExists) {
                                                professor.semesters.push({
                                                    semester: semesterName,
                                                    year: year,
                                                    semesterId: semesterId,
                                                    course_id: taught.course_id
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (error) {
                    // Skip failed requests (e.g., 404 for non-existent data)
                    console.warn(`⚠️  Failed to fetch professors for course ${course.course_id}: ${error.message}`);
                }
            });

            // Wait for batch to complete
            await Promise.allSettled(promises);
            processedCourses += batch.length;

            // Small delay between batches
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        const professors = Array.from(professorMap.values());

        const cacheData = {
            timestamp: new Date().toISOString(),
            professors: professors,
            extractionMethod: 'course-specific-api',
            coursesProcessed: processedCourses,
            cutoffYear: cutoffYear
        };

        await fs.writeFile(
            path.join(__dirname, '..', 'data', 'professors-cache.json'),
            JSON.stringify(cacheData, null, 2)
        );

        console.log(`✅ Extracted ${professors.length} professors from ${processedCourses} courses`);
        return professors.length;

    } catch (error) {
        console.error('❌ Failed to extract professors from courses:', error.message);
        return 0;
    }
}

async function generateStats() {
    console.log('📈 Generating cache statistics...');

    try {
        const coursesData = await fs.readFile(path.join(__dirname, '..', 'data', 'courses-cache.json'), 'utf8');
        const professorsData = await fs.readFile(path.join(__dirname, '..', 'data', 'professors-cache.json'), 'utf8');

        const courses = JSON.parse(coursesData);
        const professors = JSON.parse(professorsData);

        const stats = {
            timestamp: new Date().toISOString(),
            courses: courses.courses.length,
            professors: professors.professors.length,
            coursesCacheTime: courses.timestamp,
            professorsCacheTime: professors.timestamp
        };

        await fs.writeFile(
            path.join(__dirname, '..', 'data', 'cache-stats.json'),
            JSON.stringify(stats, null, 2)
        );

        console.log('\n📊 Cache Statistics:');
        console.log(`   Courses: ${stats.courses}`);
        console.log(`   Professors: ${stats.professors}`);
        console.log(`   Courses cached: ${new Date(stats.coursesCacheTime).toLocaleString()}`);
        console.log(`   Professors cached: ${new Date(stats.professorsCacheTime).toLocaleString()}`);

    } catch (error) {
        console.error('❌ Failed to generate stats:', error.message);
    }
}

async function main() {
    console.log('🚀 Starting UMD.io data caching...');

    try {
        // Ensure data directory exists
        await fs.mkdir(path.join(__dirname, '..', 'data'), { recursive: true });

        // Always cache courses (they change less frequently)
        const coursesCount = await cacheCourses();

        // Check if we need to extract professors
        const shouldExtractProfessors = process.argv.includes('--extract-professors') ||
                                       process.argv.includes('--full') ||
                                       !await fs.access(path.join(__dirname, '..', 'data', 'professors-cache.json')).then(() => true).catch(() => false);

        let professorsCount = 0;
        if (shouldExtractProfessors) {
            console.log('🔄 Extracting professors from course sections (this may take a while)...');
            professorsCount = await cacheProfessors();
        } else {
            console.log('⏭️  Skipping professor extraction (use --extract-professors to force)');
        }

        await generateStats();

        console.log('\n✅ Data caching completed successfully!');
        console.log(`📊 Cached ${coursesCount} courses${professorsCount > 0 ? ` and ${professorsCount} professors` : ''}`);

        if (professorsCount === 0) {
            console.log('💡 Tip: Run with --extract-professors to extract professor data from courses');
        }

    } catch (error) {
        console.error('\n❌ Data caching failed:', error.message);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = { main, cacheCourses, cacheProfessors };
