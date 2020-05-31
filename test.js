require('.');
var express = require('express'),
  app = module.exports = express(),

  proxy = require('http-proxy').createProxyServer({
    host: 'https://postman-echo.com'
    // port: 80
  });

app.use('/', function (req, res, next) {
  proxy.web(req, res, {
    target: 'https://postman-echo.com'
  }, next);
});

app.listen(3030, function () {
  console.info('Listening!');
});
