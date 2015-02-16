module.exports = function(grunt) {
    var src = ["*.js", "decode/**/*.js"];
    grunt.initConfig({
        jshint: {
            options: {
                jshintrc: true
            },
            files: {
                src: src
            }
        },
        mochaTest: {
            test: {
                src: ["spec/**/*.spec.js"],
                options: {
                    reporter: "spec"
              }
            }
          }

    });

    grunt.loadNpmTasks("grunt-mocha-test");
    grunt.loadNpmTasks("grunt-contrib-jshint");

    // Default task(s).
    grunt.registerTask("default", ["jshint", "mochaTest:test"]);
};