/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {

  // Specify the test environment
  testEnvironment: 'node',

  // Match test files that end with .test.ts inside the tests folder
  testMatch: ['**/tests/**/*.test.ts'],

  // Enable and configure code coverage
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov'],

  // Map .js imports to their .ts source files for testing
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
};