const newman = require('newman');

describe('Echo-Sample', function () {
  it('request methods', function (done) {
    var collection = 'test/fixtures/request-methods.postman_collection.json';

    newman.run({
      collection
    }, function (err) {
      expect(err).to.be.null;
      done();
    });
  });

  it('headers', function (done) {
    var collection = 'test/fixtures/headers.postman_collection.json';

    newman.run({
      collection
    }, function (err) {
      expect(err).to.be.null;
      done();
    });
  });

  it('authentication methods', function (done) {
    var collection = 'test/fixtures/authentication-methods.postman_collection.json';

    newman.run({
      collection
    }, function (err) {
      expect(err).to.be.null;
      done();
    });
  });

  it('utilities', function (done) {
    var collection = 'test/fixtures/utilities.postman_collection.json';

    newman.run({
      collection
    }, function (err) {
      expect(err).to.be.null;
      done();
    });
  });

  it('date and time utilities', function (done) {
    var collection = 'test/fixtures/utilities-data-time.postman_collection.json';

    newman.run({
      collection
    }, function (err) {
      expect(err).to.be.null;
      done();
    });
  });

  it('cookie manipulation', function (done) {
    var collection = 'test/fixtures/cookie-manipulation.postman_collection.json';

    newman.run({
      collection
    }, function (err) {
      expect(err).to.be.null;
      done();
    });
  });
});
