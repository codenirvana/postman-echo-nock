const TEST_TYPE = ((argv) => {
  let match = argv[argv.length - 1].match(/npm\/test-(\w+).js/);

  return match && match[1] || '';
})(process.argv);

function configOverrides (testType) {
switch (testType) {
  case 'unit':
      return {
          statements: 90,
          branches: 60,
          functions: 88,
          lines: 90
      };
  default:
      return {}
}
}

module.exports = {
  all: true,
  'check-coverage': true,
  'report-dir': '.coverage',
  'temp-dir': '.nyc_output',
  include: ['nock/*.js'],
  reporter: ['lcov', 'json', 'text', 'text-summary'],
  ...configOverrides(TEST_TYPE),
};
