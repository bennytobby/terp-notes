const fs = require('fs').promises;
const path = require('path');
const https = require('https');

// Configuration
const UMD_API_BASE = 'https://api.umd.io/v1';
const BATCH_SIZE = 50;
const DELAY_BETWEEN_BATCHES = 1000; // 1 second

async function fetchUMDData(endpoint) {
    return new Promise((resolve, reject) => {
        const url = `${UMD_API_BASE}${endpoint}`;
        console.log(`📡 Fetching: ${url}`);

        https.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const jsonData = JSON.parse(data);
                    resolve(jsonData);
                } catch (error) {
                    reject(error);
                }
            });
        }).on('error', reject);
    });
}

async function fetchAllCourses() {
    console.log('📚 Fetching all courses...');
    const courses = await fetchUMDData('/courses/list');
    console.log(`✅ Fetched ${courses.length} courses`);
    return courses;
}

async function fetchProfessorsForCourse(courseId) {
    try {
        const professors = await fetchUMDData(`/professors?course_id=${courseId}`);
        return professors || [];
    } catch (error) {
        // 404 errors are expected for courses without professors
        if (error.message.includes('404')) {
            return [];
        }
        throw error;
    }
}

async function generateOptimizedCache() {
    try {
        console.log('🚀 Starting optimized cache generation...');

        // Fetch all courses
        const courses = await fetchAllCourses();

        // Create the optimized cache structure
        const optimizedCache = {
            metadata: {
                generated: new Date().toISOString(),
                type: 'optimized-multi-cache',
                coursesCount: courses.length,
                structure: 'professor -> courses -> semesters, course -> professors -> semesters, semester-year lookup'
            },
            professors: {},
            courses: {},
            semesters: new Set(),
            years: new Set(),
            semesterYearCombinations: []
        };

        console.log(`📊 Processing ${courses.length} courses for professor data...`);

        let processedCourses = 0;
        let professorCount = 0;

        for (const course of courses) {
            try {
                const professors = await fetchProfessorsForCourse(course.course_id);

                // Add course to courses cache
                optimizedCache.courses[course.course_id] = {
                    courseInfo: {
                        id: course.course_id,
                        name: course.name
                    },
                    professors: {}
                };

                // Process professors for this course
                for (const professor of professors) {
                    const professorName = professor.name;

                    // Add professor to professors cache
                    if (!optimizedCache.professors[professorName]) {
                        optimizedCache.professors[professorName] = {};
                        professorCount++;
                    }

                    // Add course to professor's courses
                    if (!optimizedCache.professors[professorName][course.course_id]) {
                        optimizedCache.professors[professorName][course.course_id] = [];
                    }

                    // Process each semester the professor taught this course
                    const relevantTeachings = professor.taught.filter(teaching => teaching.course_id === course.course_id);

                    for (const teaching of relevantTeachings) {
                        // Parse semester format (e.g., "202508" = Fall 2025)
                        const semesterCode = teaching.semester;
                        const year = parseInt(semesterCode.substring(0, 4));
                        const semesterNum = parseInt(semesterCode.substring(4, 6));

                        let semesterName;
                        if (semesterNum === 1) semesterName = 'Spring';
                        else if (semesterNum === 5) semesterName = 'Summer';
                        else if (semesterNum === 8) semesterName = 'Fall';
                        else semesterName = 'Unknown';

                        // Add semester data
                        const semesterData = {
                            semester: semesterName,
                            year: year,
                            semesterId: semesterCode
                        };

                        optimizedCache.professors[professorName][course.course_id].push(semesterData);

                        // Add to semester/year sets
                        optimizedCache.semesters.add(semesterName);
                        optimizedCache.years.add(year);
                        optimizedCache.semesterYearCombinations.push({
                            semester: semesterName,
                            year: year,
                            semesterId: semesterCode
                        });
                    }

                    // Set professors for this course (only if we found teachings for this course)
                    if (relevantTeachings.length > 0) {
                        optimizedCache.courses[course.course_id].professors[professorName] = optimizedCache.professors[professorName][course.course_id];
                    }
                }

                processedCourses++;

                // Progress update
                if (processedCourses % 100 === 0) {
                    console.log(`📈 Progress: ${processedCourses}/${courses.length} courses processed, ${professorCount} professors found`);
                }

                // Small delay to be respectful to the API
                if (processedCourses % BATCH_SIZE === 0) {
                    await new Promise(resolve => setTimeout(resolve, DELAY_BETWEEN_BATCHES));
                }

            } catch (error) {
                console.error(`❌ Error processing course ${course.course_id}:`, error.message);
                // Continue with next course
            }
        }

        // Convert Sets to Arrays and sort
        optimizedCache.semesters = Array.from(optimizedCache.semesters).sort();
        optimizedCache.years = Array.from(optimizedCache.years).sort((a, b) => b - a);

        // Remove duplicates from combinations and sort
        const uniqueCombinations = optimizedCache.semesterYearCombinations.filter((combo, index, self) =>
            index === self.findIndex(c => c.semester === combo.semester && c.year === combo.year)
        );
        optimizedCache.semesterYearCombinations = uniqueCombinations.sort((a, b) => {
            if (a.year !== b.year) return b.year - a.year;
            const semesterOrder = { 'Fall': 0, 'Spring': 1, 'Summer': 2 };
            return (semesterOrder[a.semester] || 3) - (semesterOrder[b.semester] || 3);
        });

        // Create separate cache files
        const professorCache = {
            metadata: {
                generated: new Date().toISOString(),
                type: 'professor-indexed',
                professorsCount: Object.keys(optimizedCache.professors).length,
                structure: 'professor -> courses -> semesters'
            },
            professors: optimizedCache.professors
        };

        const courseCache = {
            metadata: {
                generated: new Date().toISOString(),
                type: 'course-indexed',
                coursesCount: Object.keys(optimizedCache.courses).length,
                structure: 'course -> professors -> semesters'
            },
            courses: optimizedCache.courses
        };

        const semesterYearCache = {
            metadata: {
                generated: new Date().toISOString(),
                type: 'semester-year-lookup',
                structure: 'semesters and years available'
            },
            semesters: optimizedCache.semesters,
            years: optimizedCache.years,
            semesterYearCombinations: optimizedCache.semesterYearCombinations
        };

        // Write cache files
        console.log('💾 Writing cache files...');
        await fs.writeFile(
            path.join(__dirname, '..', 'data', 'professor-cache.json'),
            JSON.stringify(professorCache, null, 2)
        );

        await fs.writeFile(
            path.join(__dirname, '..', 'data', 'course-cache.json'),
            JSON.stringify(courseCache, null, 2)
        );

        await fs.writeFile(
            path.join(__dirname, '..', 'data', 'semester-year-cache.json'),
            JSON.stringify(semesterYearCache, null, 2)
        );

        console.log('✅ Optimized cache generation completed successfully!');
        console.log(`📊 Final Statistics:`);
        console.log(`   - Courses: ${Object.keys(optimizedCache.courses).length}`);
        console.log(`   - Professors: ${Object.keys(optimizedCache.professors).length}`);
        console.log(`   - Semesters: ${optimizedCache.semesters.length}`);
        console.log(`   - Years: ${optimizedCache.years.length}`);
        console.log(`   - Unique semester-year combinations: ${optimizedCache.semesterYearCombinations.length}`);

    } catch (error) {
        console.error('❌ Error generating optimized cache:', error);
        process.exit(1);
    }
}

// Run the script
generateOptimizedCache();
