# Postman Echo Nock

Postman Echo Nock is a NodeJS module that mocks various endpoints under [Postman-Echo](https://docs.postman-echo.com/?version=latest) APIs. This module is created to 
fasten the testing process in all the Postman systems that uses these APIs for testing.

## Installing the Postman Echo Nock

Postman Echo Nock will be shortly available in NPM. Currently, it can be cloned from this repository. 

## Getting Started

To make use of the nock, include the module before running your tests as follows:

```javascript
include('postman-echo-nock');
```

This will intercept all the requests to the mocked endpoints and respond to those without actually making a network call!
