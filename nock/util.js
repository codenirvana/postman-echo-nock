const _ = require('lodash'),
  str = require('string-to-stream'),
  Busboy = require('busboy'),
  Url = require('url'),

  ECHO_HOST = 'https://postman-echo.com',

  multipartFormParser = (req, reqBody, callback) => {
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
      if (_.has(req.form, fieldname)) {
        req.form[fieldname] = [req.form[fieldname], val];
      }
      else if (Array.isArray(req.form[fieldname])) {
        req.form[fieldname].push(val);
      }
      else {
        req.form[fieldname] = val;
      }
    });
    busboy.on('finish', function () {
      callback(null, req);
    });

    str(reqBody).pipe(busboy);
  };


module.exports = {
  authInfoParser (authData) {
    var authenticationObj = {};

    authData.split(',').forEach(function (d) {
      d = d.split('=');

      authenticationObj[d[0].replace(' ', '')] = d[1].replace(/"/g, '');
    });

    return authenticationObj;
  },

  bodyParser (uri, reqBody, callback) {
    const url = Url.parse(decodeURIComponent(ECHO_HOST + uri), true),
      req = {
        args: url.query,
        data: {},
        files: {},
        form: {},
        headers: this.req.headers,
        json: null,
        url: ECHO_HOST + uri
      },
      contentType = req.headers && req.headers['content-type'];

    if (contentType && _.includes(contentType, 'multipart/form-data') ||
      contentType === 'application/x-www-form-urlencoded') {
      return multipartFormParser(req, reqBody, callback);
    }

    req.data = reqBody;

    if (contentType === 'application/json') {
      try {
        const json = JSON.parse(reqBody);

        req.data = req.json = json;
      }
      catch (e) {
        req.data = reqBody;
      }
    }

    callback(null, req);
  }
};
