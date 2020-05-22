module.exports = {
  cachedFiles : {
    "newman-sample-github-collection" : {
      html:`<!DOCTYPE html>
        <html>

        <head>
          <title>Hello World!</title>
        </head>

        <body>
          <h1>Hello World!</h1>
        </body>

        </html>`.replace(/(( {2})|\n)/g,''),

      xml:`<?xml version="1.0" encoding="utf-8"?>
        <food>
          <key>Homestyle Breakfast</key>
          <value>950</value>
        </food>`.replace(/(( {2})|\n)/g,'')
    }
  }
}
