const _ = require('lodash'),
  nock = require('nock'),
  Url = require('url'),
  {Readable} = require('stream'),
  Busboy = require('busboy'),
  str = require('string-to-stream'),
  btoa = require('btoa'),
  crypto = require('crypto-js'),
  zlib = require('zlib'),
  qs = require('qs'),
  cookie = require('cookie'),
  Hawk = require('hawk'),
  moment = require('moment'),
  EncodingService = require('./EncodingService'),

  ECHO_HOST = 'https://postman-echo.com',

  AUTH = 'auth',
  COLON = ':',
  AUTH_INT = 'auth-int',
  MD5_SESS = 'MD5-sess',


  getQueryParams = function (queryString) {
    if (!queryString) return {};

    return queryString.split('&').reduce((args, query) => {
      const arg = query.split(/=(.+)/); // first match

      args[arg[0]] = arg[1];

      return args;
    }, {})
  },

  authInfoParser = function (authData) {
    var authenticationObj = {};
    authData.split(', ').forEach(function (d) {
        d = d.split('=');

        authenticationObj[d[0]] = d[1].replace(/"/g, '');
    });
    return authenticationObj;
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
    'set-cookie': 'sails.sid=0123456789; Path=/'
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


/***** Authentication Methods *****/

// Basic Auth
Echo
  .get('/basic-auth')
  .query(true)
  .reply(function (uri, body) {
    var user = {
      username: 'postman',
      password: 'password'
    };

    if (this.req.headers.authorization &&
        this.req.headers.authorization.replace(/^Basic /, '') === btoa(user.username+':'+user.password)) {
          return [
            200,
            { authenticated: true }
          ];
    }

    return [
      401,
      'Unauthorized'
    ];
  });

// DigestAuth Success
Echo
  .get('/digest-auth')
  .query(true)
  .reply(function (uri, body) {
    var authInfo,
      A0,
      A1,
      A2,
      reqDigest,
      user = {
        username: 'postman',
        password: 'password',
        realm: 'Users'
      },
      unauthorizedResponse = [
        401,
        'Unauthorized',
        {
          'WWW-Authenticate': `Digest realm="Users",qop="auth",nonce="${Math.random()}"`
        }
      ];

    if(!this.req.headers.authorization) { return unauthorizedResponse; }

    authInfo = this.req.headers.authorization.replace(/^Digest /, '');
    authInfo = authInfoParser(authInfo);

    if (authInfo.username !== user.username) {
      return unauthorizedResponse;
    }

    if (authInfo.algorithm === MD5_SESS) {
      A0 = crypto.MD5(authInfo.username + COLON + user.realm + COLON + user.password).toString();
      A1 = A0 + COLON + authInfo.nonce + COLON + authInfo.cnonce;
    }
    else {
        A1 = authInfo.username + COLON + user.realm + COLON + user.password;
    }

    if (authInfo.qop === AUTH_INT) {
        A2 = 'GET' + COLON + authInfo.uri + COLON + crypto.MD5(body);
    }
    else {
        A2 = 'GET' + COLON + authInfo.uri;
    }

    A1 = crypto.MD5(A1).toString();
    A2 = crypto.MD5(A2).toString();

    if (authInfo.qop === AUTH || authInfo.qop === AUTH_INT) {
        reqDigest = crypto.MD5([A1, authInfo.nonce, authInfo.nc, authInfo.cnonce, authInfo.qop, A2].join(COLON)).toString();
    }
    else {
        reqDigest = crypto.MD5([A1, authInfo.nonce, A2].join(COLON)).toString();
    }

    if (reqDigest === authInfo.response) {
      return [
        200,
        { authenticated: true }
      ]
    }

    return unauthorizedResponse;
  });

// Hawk Auth
Echo
  .get('/auth/hawk')
  .query(true)
  .reply(function (uri, body, callback) {
    var response;

    Hawk.server.authenticate(this.req, function () {
      return {
        key: 'uabsddiasndiuasbdiuasdbasiudbasiu',
        algorithm: 'sha256',
        user : 'Postman'
      };
    }).then(function () {
      console.log('------------------------------');
    })
    .catch(function (err) {
      console.log('********************************');
      console.log(err);
      callback(null, [
        401,
        'rETRY',
        {
          'Server-Authorization': Hawk.server.header(err.credentials, err.artifacts)
        }
      ]);
    });
  });


/***** Cookie Manipulation *****/

// Set Cookies
Echo
  .get('/cookies/set')
  .query(true)
  .reply(function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString);
      queries['sails.sid'] = '0123456789';//else, the default set cookies are replaced

      return [
        302,
        'Found. Redirecting to /cookies',
        {
          'Location': '/cookies',
          'set-cookie': _.transform(queries, function (result, value, key) {
              result.push(`${key}=${value}; Path=/`);
            }, [])
        }
      ]
  });

// Get Cookies
// @Todo: Why add "sails.sid": "0123456789" cookie in default headers?
Echo
  .get('/cookies')
  .query(true)
  .reply(200, function (uri, body) {
    var cookieString = this.req.headers.cookie || '',
      cookies = cookie.parse(cookieString);

      return {
        cookies: cookies
      };
  });

// Delete Cookies
Echo
  .get('/cookies/delete')
  .query(true)
  .reply(function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString);

      return [
        302,
        'Found. Redirecting to /cookies',
        {
          'Location': '/cookies',
          'set-cookie': _.transform(queries, function (result, value, key) {
              result.push(`${key}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
            }, [])
        }
      ]
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

// Streamed Response
Echo
  .get(/^\/stream\/\d+$/)
  .query(true)
  .reply(200, function (uri) {
    var frequency = uri.split('/')[2],
      url = Url.parse(this.basePath + uri),
      singleResponse = JSON.stringify({
        args: {
          n: frequency
        },
        headers: this.req.headers,
        url: url.href
      }, null, 2),

      body = new Readable({
        read(){
          frequency-- ? this.push(singleResponse):this.push(null);
        }
      });

      return body;
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

// Get UTF8 Encoded Response
Echo
  .get('/encoding/utf8')
  .query(true)
  .reply(200, EncodingService.utf8Text, {
    'content-type': 'text/html; charset=utf-8'
  });

// GZip Compressed Response
Echo
  .get('/gzip')
  .query(true)
  .reply(200, function (uri, body) {
    var data = {
        gzipped: true,
        headers: this.req.headers,
        method: 'GET'
      },
      buffer = Buffer.from(JSON.stringify(data, null, 2), 'utf8');
      return zlib.gzipSync(buffer);
  }, {
    'Content-Encoding': 'gzip',
    'Content-Type': 'application/json'
  });

// Deflate Compressed Response
Echo
  .get('/deflate')
  .query(true)
  .reply(200, function (uri, body) {
    var data = {
        deflated: true,
        headers: this.req.headers,
        method: 'GET'
      },
      buffer = Buffer.from(JSON.stringify(data, null, 2), 'utf8');
      return zlib.deflateSync(buffer);
  }, {
    'Content-Encoding': 'deflate',
    'Content-Type': 'application/json'
  });

// IP address in JSON format
Echo
  .get('/ip')
  .query(true)
  .reply(200, {
    "ip": "127.0.0.1"     // localhost IP for nocked requests
  });


/***** Utilities / Date and Time *****/

// Current UTC time
Echo
  .get('/time/now')
  .query(true)
  .reply(200, (new Date()).toUTCString());

// Timestamp validity
Echo
  .get('/time/valid')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        valid: createdMoment.isValid()
      };
  });

// Format timestamp
Echo
  .get('/time/format')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        format: createdMoment.format(queries.format)
      };
  });

// Extract timestamp unit
Echo
  .get('/time/unit')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        unit: createdMoment.get(queries.unit || 'year')
      };
  });

// Time addition
Echo
  .get('/time/add')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      addParams = _.pick(queries, ['years', 'months', 'days', 'hours', 'minutes', 'seconds', 'milliseconds']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        sum: createdMoment.add(addParams).toString()
      };
  });

// Time subtraction
Echo
  .get('/time/subtract')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      addParams = _.pick(queries, ['years', 'months', 'days', 'hours', 'minutes', 'seconds', 'milliseconds']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        sum: createdMoment.subtract(addParams).toString()
      };
  });

// Start of time
Echo
  .get('/time/start')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        start: createdMoment.startOf(queries.unit).toString()
      };
  });

// Object representation
Echo
  .get('/time/object')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return createdMoment.toObject();
  });

// Before comparisons
Echo
  .get('/time/before')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        before: createdMoment.isBefore(queries.target)
      };
  });

// After comparisons
Echo
  .get('/time/after')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        after: createdMoment.isAfter(queries.target)
      };
  });

// Between timestamps
Echo
  .get('/time/between')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        between: createdMoment.isBetween(queries.start, queries.end, queries.unit)
      };
  });

// Leap year check
Echo
  .get('/time/leap')
  .query(true)
  .reply(200, function (uri, body) {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

      return {
        leap: createdMoment.isLeapYear()
      };
  });

module.exports = Echo;
