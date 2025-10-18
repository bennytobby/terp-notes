const fs = require('fs').promises;
const path = require('path');

async function createMultipleCaches() {
    try {
        console.log('🔄 Reading optimized cache...');
        const optimizedCachePath = path.join(__dirname, '..', 'data', 'optimized-cache.json');
        const optimizedCacheData = await fs.readFile(optimizedCachePath, 'utf8');
        const optimizedCache = JSON.parse(optimizedCacheData);

        console.log('📊 Creating professor-indexed cache...');
        // Professor-indexed cache: Professor -> Courses -> Semesters
        const professorCache = {
            metadata: {
                generated: new Date().toISOString(),
                type: 'professor-indexed',
                professorsCount: Object.keys(optimizedCache.professors).length,
                structure: 'professor -> courses -> semesters'
            },
            professors: optimizedCache.professors
        };

        console.log('📊 Creating course-indexed cache...');
        // Course-indexed cache: Course -> Professors -> Semesters
        const courseCache = {
            metadata: {
                generated: new Date().toISOString(),
                type: 'course-indexed',
                coursesCount: 0,
                structure: 'course -> professors -> semesters'
            },
            courses: {}
        };

        // Build course-indexed cache from professor data
        let courseCount = 0;
        for (const [professorName, courses] of Object.entries(optimizedCache.professors)) {
            for (const [courseId, semesters] of Object.entries(courses)) {
                if (!courseCache.courses[courseId]) {
                    courseCache.courses[courseId] = {
                        professors: {},
                        courseInfo: {
                            id: courseId,
                            name: `Course ${courseId}` // We'll need to get actual course names
                        }
                    };
                    courseCount++;
                }

                if (!courseCache.courses[courseId].professors[professorName]) {
                    courseCache.courses[courseId].professors[professorName] = [];
                }

                // Add semesters for this professor teaching this course
                courseCache.courses[courseId].professors[professorName] = semesters;
            }
        }
        courseCache.metadata.coursesCount = courseCount;

        console.log('📊 Creating semester-year lookup cache...');
        // Semester-year lookup: All unique semester-year combinations
        const semesterYearCache = {
            metadata: {
                generated: new Date().toISOString(),
                type: 'semester-year-lookup',
                structure: 'semesters and years available'
            },
            semesters: new Set(),
            years: new Set(),
            semesterYearCombinations: []
        };

        // Extract all unique semesters and years
        for (const [professorName, courses] of Object.entries(optimizedCache.professors)) {
            for (const [courseId, semesters] of Object.entries(courses)) {
                for (const semesterData of semesters) {
                    semesterYearCache.semesters.add(semesterData.semester);
                    semesterYearCache.years.add(semesterData.year);
                    semesterYearCache.semesterYearCombinations.push({
                        semester: semesterData.semester,
                        year: semesterData.year,
                        semesterId: semesterData.semesterId
                    });
                }
            }
        }

        // Convert Sets to Arrays and sort
        semesterYearCache.semesters = Array.from(semesterYearCache.semesters).sort();
        semesterYearCache.years = Array.from(semesterYearCache.years).sort((a, b) => b - a);

        // Remove duplicates from combinations and sort
        const uniqueCombinations = semesterYearCache.semesterYearCombinations.filter((combo, index, self) =>
            index === self.findIndex(c => c.semester === combo.semester && c.year === combo.year)
        );
        semesterYearCache.semesterYearCombinations = uniqueCombinations.sort((a, b) => {
            if (a.year !== b.year) return b.year - a.year; // Most recent first
            const semesterOrder = { 'Fall': 0, 'Spring': 1, 'Summer': 2 };
            return (semesterOrder[a.semester] || 3) - (semesterOrder[b.semester] || 3);
        });

        // Write all caches
        console.log('💾 Writing professor-indexed cache...');
        await fs.writeFile(
            path.join(__dirname, '..', 'data', 'professor-cache.json'),
            JSON.stringify(professorCache, null, 2)
        );

        console.log('💾 Writing course-indexed cache...');
        await fs.writeFile(
            path.join(__dirname, '..', 'data', 'course-cache.json'),
            JSON.stringify(courseCache, null, 2)
        );

        console.log('💾 Writing semester-year lookup cache...');
        await fs.writeFile(
            path.join(__dirname, '..', 'data', 'semester-year-cache.json'),
            JSON.stringify(semesterYearCache, null, 2)
        );

        console.log('✅ Multiple caches created successfully!');
        console.log(`📊 Professor cache: ${Object.keys(professorCache.professors).length} professors`);
        console.log(`📊 Course cache: ${courseCache.metadata.coursesCount} courses`);
        console.log(`📊 Semester-year cache: ${semesterYearCache.semesters.length} semesters, ${semesterYearCache.years.length} years`);
        console.log(`📊 Unique semester-year combinations: ${semesterYearCache.semesterYearCombinations.length}`);

    } catch (error) {
        console.error('❌ Error creating multiple caches:', error);
        process.exit(1);
    }
}

createMultipleCaches();
