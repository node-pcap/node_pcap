module.exports = function(grunt) {
    var src = ["*.js", "decode/**/*.js"];
    var tests = ["spec/**/*.spec.js"];
    var allJs = tests.concat(src);
    grunt.initConfig({
        jshint: {
            options: {
                jshintrc: true
            },
            files: {
                src: allJs
            }
        },
        mochaTest: {
            test: {
                src: allJs,
            }
        },
        mocha_istanbul: {
            coverage: {
                src: allJs,
                options: {
                    reportFormats: ["text", "html"],
                    excludes: tests
                }
            }
        }
    });

    grunt.loadNpmTasks("grunt-mocha-test");
    grunt.loadNpmTasks("grunt-contrib-jshint");
    grunt.loadNpmTasks("grunt-mocha-istanbul");

    // Default task(s).
    grunt.registerTask("cover", ["mocha_istanbul:coverage"]);
    grunt.registerTask("default", ["jshint", "mochaTest:test"]);
};