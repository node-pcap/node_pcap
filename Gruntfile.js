module.exports = function(grunt) {
    grunt.initConfig({
        jshint: {
            options: {
                jshintrc: true
            },
            files: {
                src: ["*.js", "decode/**/*.js"]
            }
        }
    });

    grunt.loadNpmTasks("grunt-contrib-jshint");

    // Default task(s).
    grunt.registerTask("default", ["jshint"]);
};