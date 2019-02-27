const nock = require('nock'),
  Url = require('url'),
  Busboy = require('busboy'),
  str = require('string-to-stream'),

  ECHO_HOST = 'https://postman-echo.com',

  getQueryParams = function (queryString) {
    if (!queryString) return {};

    return queryString.split('&').reduce((args, query) => {
      const arg = query.split(/=(.+)/); // first match

      args[arg[0]] = arg[1];

      return args;
    }, {})
  },

  multipartFormParser = function (req, reqBody, callback) {
    const busboy = new Busboy({
        headers: req.headers
      }),
      DATA_URI = 'data:application/octet-stream;base64,';

    busboy.on('file', function (fieldname, file, filename) {
      let buffer = Buffer.from('');

      file.on('data', function (data) {
        buffer = Buffer.concat([buffer, data]);
      });

      file.on('end', function () {
        req.files[filename] = DATA_URI + buffer.toString('base64');
      });
    });
    busboy.on('field', function (fieldname, val) {
      if (req.form.hasOwnProperty(fieldname)) {
        req.form[fieldname] = [req.form[fieldname], val];
      } else if (Array.isArray(req.form[fieldname])) {
        req.form[fieldname].push(val);
      } else {
        req.form[fieldname] = val;
      }
    });
    busboy.on('finish', function () {
      callback(null, req)
    });

    str(reqBody).pipe(busboy);
  },

  bodyParser = function (uri, reqBody, callback) {
    const url = Url.parse(decodeURIComponent(this.basePath + uri));
    req = {
        args: getQueryParams(url.query),
        data: {},
        files: {},
        form: {},
        headers: this.req.headers,
        json: null,
        url: url.href
      },
      contentType = req.headers && req.headers['content-type'];

    if (contentType && contentType.indexOf('multipart/form-data') >= 0 || contentType === 'application/x-www-form-urlencoded') {
      return multipartFormParser(req, reqBody, callback);
    }

    req.data = reqBody;

    if (contentType === 'application/json') {
      try {
        const json = JSON.parse(reqBody);
        req.data = req.json = json;
      } catch (e) {
        req.data = reqBody;
      }
    }

    callback(null, req);
  },

  Echo = nock(ECHO_HOST)
  .persist()
  .replyContentLength()
  .replyDate()
  .defaultReplyHeaders({
    Connection: 'keep-alive',
    ETag: '0123456789',
    Server: 'Nock',
    Vary: 'Accept-Encoding',
    'set-cookie': 'sails.sid=0123456789; Path=/; HttpOnly'
  });

/***** Request Methods *****/

// GET Request
Echo
  .get('/get')
  .query(true)
  .reply(200, function (uri) {
    const url = Url.parse(this.basePath + uri);

    return JSON.stringify({
      args: getQueryParams(url.query),
      headers: this.req.headers,
      url: url.href
    })
  }, {
    'content-type': 'application/json; charset=utf-8'
  });

// POST Request
Echo
  .post('/post')
  .query(true)
  .reply(200, bodyParser);

// PUT Request
Echo
  .put('/put')
  .query(true)
  .reply(200, bodyParser);

// PATCH Request
Echo
  .patch('/patch')
  .query(true)
  .reply(200, bodyParser);

// DELETE Request
Echo
  .delete('/delete')
  .query(true)
  .reply(200, bodyParser);


/***** Headers *****/

// Request Headers
Echo
  .get('/headers')
  .query(true)
  .reply(200, function () {
    return {
      headers: this.req.headers
    };
  });

// Response Headers
Echo
  .get('/response-headers')
  .query(true)
  .reply(function (uri) {
    const url = Url.parse(this.basePath + uri),
      headers = getQueryParams(url.query);

    return [200, headers, headers];
  });


/***** Utilities *****/

// Response Status Code
Echo
  .get(/^\/status\/[1-5][0-9][0-9]$/)
  .query(true)
  .reply(function (uri) {
    const status = parseInt(uri.substr(-3));

    return [status, {
      status
    }]
  });

// Delay Response
Echo
  .get(/^\/delay\/\d+$/)
  .query(true)
  .reply(200, function (uri, body, callback) {
    const delay = uri.split('/')[2];
    setTimeout(() => {
      callback(null, {delay})
    }, parseInt(delay * 1000));
  });

module.exports = Echo;