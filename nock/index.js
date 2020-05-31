const _ = require('lodash'),
  nock = require('nock'),
  Url = require('url'),
  util = require('./util'),
  { Readable } = require('stream'),
  btoa = require('btoa'),
  crypto = require('crypto-js'),
  zlib = require('zlib'),
  qs = require('qs'),
  cookie = require('cookie'),
  Hawk = require('hawk'),
  moment = require('moment'),
  cachedFiles = require('./cached-files'),

  ECHO_HOST = 'https://postman-echo.com',

  AUTH = 'auth',
  COLON = ':',
  AUTH_INT = 'auth-int',
  MD5_SESS = 'MD5-sess',
  OAUTH_SIGNATURE = 'oauth_signature',

  OAUTH_KEY = 'D+EdQ-gs$-%@2Nu7',
  BASIC_AUTH_USERNAME = 'postman',
  BASIC_AUTH_PASSWORD = 'password',
  DIGEST_AUTH_USERNAME = 'postman',
  DIGEST_AUTH_PASSWORD = 'password',
  DIGEST_AUTH_REALM = 'Users',
  HAWK_AUTH_KEY = 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
  HAWK_AUTH_ALGORITHM = 'sha256',
  HAWK_AUTH_USER = 'Postman',


  Echo = nock(ECHO_HOST,
    {
      allowUnmocked: true // allow requests to unmocked routes to actually make a HTTP request
    })
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


/** *** Request Methods *****/

// GET Request
Echo
  .get('/get')
  .query(true)
  .reply(200, function (uri) {
    const url = Url.parse(decodeURIComponent(ECHO_HOST + uri), true);

    return JSON.stringify({
      args: url.query,
      headers: this.req.headers,
      url: ECHO_HOST + uri
    });
  }, {
    'content-type': 'application/json; charset=utf-8'
  });

// POST Request
Echo
  .post('/post')
  .query(true)
  .reply(200, util.bodyParser);

// PUT Request
Echo
  .put('/put')
  .query(true)
  .reply(200, util.bodyParser);


// PATCH Request
Echo
  .patch('/patch')
  .query(true)
  .reply(200, util.bodyParser);

// DELETE Request
Echo
  .delete('/delete')
  .query(true)
  .reply(200, util.bodyParser);


/** *** Headers *****/

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
    const url = Url.parse(decodeURIComponent(ECHO_HOST + uri), true),
      headers = url.query;

    return [200, JSON.stringify(headers, null, 4), headers];
  });


/** *** Authentication Methods *****/

// Basic Auth
Echo
  .get('/basic-auth')
  .query(true)
  .reply(function () {
    var user = {
      username: BASIC_AUTH_USERNAME,
      password: BASIC_AUTH_PASSWORD
    };

    if (this.req.headers.authorization &&
        this.req.headers.authorization.replace(/^Basic /, '') === btoa(user.username + ':' + user.password)) {
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
  .reply(function (_uri, body) {
    var authInfo,
      A0,
      A1,
      A2,
      reqDigest,
      user = {
        username: DIGEST_AUTH_USERNAME,
        password: DIGEST_AUTH_PASSWORD,
        realm: DIGEST_AUTH_REALM
      },
      unauthorizedResponse = [
        401,
        'Unauthorized',
        {
          'WWW-Authenticate': `Digest realm="Users",qop="auth",nonce="${Math.random()}"`
        }
      ];

    if (!this.req.headers.authorization) { return unauthorizedResponse; }

    authInfo = this.req.headers.authorization.replace(/^Digest /, '');
    authInfo = util.authInfoParser(authInfo);

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
      reqDigest = crypto.MD5([A1, authInfo.nonce, authInfo.nc, authInfo.cnonce, authInfo.qop, A2]
        .join(COLON)).toString();
    }
    else {
      reqDigest = crypto.MD5([A1, authInfo.nonce, A2].join(COLON)).toString();
    }

    if (reqDigest === authInfo.response) {
      return [
        200,
        { authenticated: true }
      ];
    }

    return unauthorizedResponse;
  });

// Hawk Auth
Echo
  .get('/auth/hawk')
  .query(true)
  .reply(function (uri, _body, callback) {
    // the request object of the nock is an altered one, hence the following fixes
    this.req.url = uri;
    this.req.headers.host === 'postman-echo.com' && (this.req.connection.encrypted = true);
    // false while testing using localhost

    Hawk.server.authenticate(this.req, function () {
      return {
        key: HAWK_AUTH_KEY,
        algorithm: HAWK_AUTH_ALGORITHM,
        user: HAWK_AUTH_USER
      };
    }).then(function () {
      callback(null, [
        200,
        {
          message: 'Hawk Authentication Successful'
        }
      ]);
    })
      .catch(function (err) {
        callback(null, [
          401,
          'rETRY',
          {
            'Server-Authorization': Hawk.server.header(err.credentials, err.artifacts)
          }
        ]);
      });
  });

// OAuth1.0 (verify signature)
Echo
  .get('/oauth1')
  .query(true)
  .reply(function (uri) {
    const authInfo = util.authInfoParser(this.req.headers.authorization.replace(/^OAuth /, '')),
      url = Url.parse((ECHO_HOST + uri), true),
      baseUri = ECHO_HOST + url.pathname,
      parameters = {
        ...url.query,
        ...authInfo
      },

      normalizedParamString = Object
        .keys(_.omit(parameters, [OAUTH_SIGNATURE])) // omit OAUTH_SIGNATURE which is later used in verifying
        .sort()
        .reduce((res, key) => {
          res.push(`${key}=${parameters[key]}`);

          return res;
        }, [])
        .join('&'),
      baseString = `${this.req.method}&${encodeURIComponent(baseUri)}&${encodeURIComponent(normalizedParamString)}`,

      signingKey = `${encodeURIComponent(OAUTH_KEY)}&`, // since there is no oauth_token, nothing follows '&'

      oauthSignature = encodeURIComponent(crypto.enc.Base64.stringify(crypto.HmacSHA1(baseString, signingKey)));

    if (oauthSignature === parameters[OAUTH_SIGNATURE]) {
      return [
        200,
        {
          status: 'pass',
          message: 'OAuth-1.0a signature verification was successful'
        }
      ];
    }

    return [
      401,
      {
        status: 'fail',
        message: 'HMAC-SHA1 verification failed',
        base_uri: baseUri,
        normalized_param_string: normalizedParamString,
        base_string: baseString,
        signing_key: signingKey
      }
    ];
  });


/** *** Cookie Manipulation *****/

// Set Cookies
Echo
  .get('/cookies/set')
  .query(true)
  .reply(function () {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString);

    queries['sails.sid'] = '0123456789';// else, the default set cookies are replaced

    return [
      302,
      'Found. Redirecting to /cookies',
      {
        Location: '/cookies',
        'set-cookie': _.transform(queries, function (result, value, key) {
          result.push(`${key}=${value}; Path=/`);
        }, [])
      }
    ];
  });

// Get Cookies
// @Todo: Why add "sails.sid": "0123456789" cookie in default headers?
Echo
  .get('/cookies')
  .query(true)
  .reply(200, function () {
    var cookieString = this.req.headers.cookie || '',
      cookies = cookie.parse(cookieString);

    return {
      cookies
    };
  });

// Delete Cookies
Echo
  .get('/cookies/delete')
  .query(true)
  .reply(function () {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString);

    return [
      302,
      'Found. Redirecting to /cookies',
      {
        Location: '/cookies',
        'set-cookie': _.transform(queries, function (result, value, key) {
          result.push(`${key}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
        }, [])
      }
    ];
  });


/** *** Utilities *****/

// Response Status Code
Echo
  .get(/^\/status\/[1-5][0-9][0-9]$/)
  .query(true)
  .reply(function (uri) {
    const status = parseInt(uri.substr(-3), 10);

    return [status, {
      status
    }];
  });

// Streamed Response
Echo
  .get(/^\/stream\/\d+$/)
  .query(true)
  .reply(200, function (uri) {
    var frequency = uri.split('/')[2],
      singleResponse = JSON.stringify({
        args: {
          n: frequency
        },
        headers: this.req.headers,
        url: ECHO_HOST + uri
      }, null, 2),

      body = new Readable({
        read () {
          frequency-- ? this.push(singleResponse) : this.push(null);
        }
      });

    return body;
  }, {
    'Transfer-Encoding': 'chunked'
  });

// Delay Response
Echo
  .get(/^\/delay\/\d+$/)
  .query(true)
  .reply(200, function (uri, _body, callback) {
    const delay = uri.split('/')[2];

    setTimeout(() => {
      callback(null, { delay });
    }, parseInt(delay * 1000, 10));
  });

// Get UTF8 Encoded Response
Echo
  .get('/encoding/utf8')
  .query(true)
  .reply(200, cachedFiles.utf8Text, {
    'content-type': 'text/html; charset=utf-8',
    'transfer-encoding': 'chunked'
  });

// GZip Compressed Response
Echo
  .get('/gzip')
  .query(true)
  .reply(200, function () {
    var data = {
        gzipped: true,
        headers: this.req.headers,
        method: 'GET'
      },
      buffer = Buffer.from(JSON.stringify(data, null, 2), 'utf8');

    return zlib.gzipSync(buffer);
  }, {
    'Content-Encoding': 'gzip',
    'Content-Type': 'application/json; charset=utf-8'
  });

// Deflate Compressed Response
Echo
  .get('/deflate')
  .query(true)
  .reply(200, function () {
    var data = {
        deflated: true,
        headers: this.req.headers,
        method: 'GET'
      },
      buffer = Buffer.from(JSON.stringify(data, null, 2), 'utf8');

    return zlib.deflateSync(buffer);
  }, {
    'Content-Encoding': 'deflate',
    'Content-Type': 'application/json; charset=utf-8'
  });

// IP address in JSON format
Echo
  .get('/ip')
  .query(true)
  .reply(200, {
    ip: '127.0.0.1' // localhost IP for nocked requests
  });


/** *** Utilities / Date and Time *****/

// Current UTC time
Echo
  .get('/time/now')
  .query(true)
  .reply(200, (new Date()).toUTCString());

// Timestamp validity
Echo
  .get('/time/valid')
  .query(true)
  .reply(200, function () {
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
  .reply(200, function () {
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
  .reply(200, function () {
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
  .reply(200, function () {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      addParams = _.pick(queries, ['years', 'months', 'days', 'hours', 'minutes', 'seconds', 'milliseconds']),
      createdMoment = moment.utc(momentParams.timestamp, momentParams.format, momentParams.strict);

    return {
      sum: createdMoment.add(addParams).toString()
    };
  });

// Time subtraction
Echo
  .get('/time/subtract')
  .query(true)
  .reply(200, function () {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      addParams = _.pick(queries, ['years', 'months', 'days', 'hours', 'minutes', 'seconds', 'milliseconds']),
      createdMoment = moment.utc(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

    return {
      difference: createdMoment.subtract(addParams).toString()
    };
  });

// Start of time
Echo
  .get('/time/start')
  .query(true)
  .reply(200, function () {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment.utc(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

    return {
      start: createdMoment.startOf(queries.unit).toString()
    };
  });

// Object representation
Echo
  .get('/time/object')
  .query(true)
  .reply(200, function () {
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
  .reply(200, function () {
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
  .reply(200, function () {
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
  .reply(200, function () {
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
  .reply(200, function () {
    var queryIndex = this.req.path.indexOf('?'),
      queryString = queryIndex !== -1 ? this.req.path.slice(queryIndex + 1) : '',
      queries = qs.parse(queryString),
      momentParams = _.pick(queries, ['strict', 'locale', 'format', 'timestamp']),
      createdMoment = moment(momentParams.timestamp, momentParams.format, momentParams.locale, momentParams.strict);

    return {
      leap: createdMoment.isLeapYear()
    };
  });

/** *** Newman sample echo *****/
Echo
  .get(/^\/type\/(html|xml)$/)
  .query({
    source: 'newman-sample-github-collection'
  })
  .reply(function (uri) {
    var queryIndex = this.req.path.indexOf('?'),
      type = uri.slice(0, queryIndex).split('/')[2];

    return [
      200,
      cachedFiles.type,
      {
        'content-type': `application/${type}; charset=utf-8`
      }
    ];
  });

module.exports = Echo;
