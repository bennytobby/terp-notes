const fs = require('fs').promises;
const path = require('path');

async function optimizeCache() {
    try {
        console.log('🔄 Optimizing cache structure...');

        // Read existing cache files
        const coursesCache = JSON.parse(await fs.readFile('data/courses-cache.json', 'utf8'));
        const professorsCache = JSON.parse(await fs.readFile('data/professors-cache.json', 'utf8'));

        console.log(`📚 Found ${coursesCache.courses.length} courses`);
        console.log(`👨‍🏫 Found ${professorsCache.professors.length} professors`);

        // Create optimized professor structure: Professor -> Courses -> Semesters
        const optimizedProfessors = {};

        for (const prof of professorsCache.professors) {
            if (!prof.semesters || prof.semesters.length === 0) continue;

            const profName = prof.name;
            if (!optimizedProfessors[profName]) {
                optimizedProfessors[profName] = {};
            }

            // Group semesters by course
            for (const semester of prof.semesters) {
                const courseId = semester.course_id;
                if (!optimizedProfessors[profName][courseId]) {
                    optimizedProfessors[profName][courseId] = [];
                }

                // Add semester info
                optimizedProfessors[profName][courseId].push({
                    semester: semester.semester,
                    year: semester.year,
                    semesterId: semester.semesterId
                });
            }
        }

        // Create optimized courses structure: Course -> Professors
        const optimizedCourses = {};

        for (const course of coursesCache.courses) {
            const courseId = course.course_id;
            optimizedCourses[courseId] = {
                name: course.name,
                description: course.description,
                professors: []
            };

            // Find professors who taught this course
            for (const [profName, courses] of Object.entries(optimizedProfessors)) {
                if (courses[courseId]) {
                    optimizedCourses[courseId].professors.push({
                        name: profName,
                        semesters: courses[courseId]
                    });
                }
            }
        }

        // Create final optimized cache
        const optimizedCache = {
            metadata: {
                generated: new Date().toISOString(),
                coursesCount: Object.keys(optimizedCourses).length,
                professorsCount: Object.keys(optimizedProfessors).length,
                structure: 'optimized'
            },
            professors: optimizedProfessors,
            courses: optimizedCourses
        };

        // Write optimized cache
        await fs.writeFile('data/optimized-cache.json', JSON.stringify(optimizedCache));

        console.log('✅ Optimized cache created successfully!');
        console.log(`📊 Structure: ${Object.keys(optimizedProfessors).length} professors, ${Object.keys(optimizedCourses).length} courses`);

        return optimizedCache;

    } catch (error) {
        console.error('❌ Error optimizing cache:', error);
        throw error;
    }
}

// Run if called directly
if (require.main === module) {
    optimizeCache()
        .then(() => console.log('🎉 Cache optimization complete!'))
        .catch(console.error);
}

module.exports = { optimizeCache };
