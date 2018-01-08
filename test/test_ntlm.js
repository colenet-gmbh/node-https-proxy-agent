
/**
 * Module dependencies.
 */

var fs = require('fs');
var url = require('url');
var http = require('http');
var https = require('https');
var assert = require('assert');
var Proxy = require('proxy');
var NTLMProxy = require('proxy-proxy');
var rewire = require('rewire');
var HttpsProxyAgent = rewire('../index.js');

describe('HttpsProxyAgent', function () {

    var server;
    var serverPort;

    var sslServer;
    var sslServerPort;

    var proxy;
    var proxyPort = 40000;

    var sslProxy;
    var sslProxyPort;

    before(function (done) {
        // setup target HTTP server
        server = http.createServer();
        server.listen(function () {
            serverPort = server.address().port;
            done();
        });
    });

    before(function (done) {
        // setup HTTP proxy server
        proxy = new NTLMProxy.ProxyServer();
        proxy.start(proxyPort);
        done();
    });

    before(function (done) {
        // setup target HTTPS server
        var options = {
            key: fs.readFileSync(__dirname + '/ssl-cert-snakeoil.key'),
            cert: fs.readFileSync(__dirname + '/ssl-cert-snakeoil.pem')
        };
        sslServer = https.createServer(options);
        sslServer.listen(function () {
            sslServerPort = sslServer.address().port;
            done();
        });
    });

    before(function (done) {
        // setup SSL HTTP proxy server
        var options = {
            key: fs.readFileSync(__dirname + '/ssl-cert-snakeoil.key'),
            cert: fs.readFileSync(__dirname + '/ssl-cert-snakeoil.pem')
        };
        sslProxy = Proxy(https.createServer(options));
        sslProxy.listen(function () {
            sslProxyPort = sslProxy.address().port;
            done();
        });
    });

    // shut down test HTTP server
    after(function (done) {
        server.once('close', function () { done(); });
        server.close();
    });

    after(function (done) {
        sslServer.once('close', function () { done(); });
        sslServer.close();
    });


    describe('"ntlm" module', function () {
        it('should find Negotiate in array', function(done) {
           var findNegotiate = HttpsProxyAgent.__get__('findNegotiate');
           assert.ok(findNegotiate(['Negotiate', 'NTLM']), "true case");
           assert.equal(findNegotiate(['NTLM']), false, "No negotiate");
           done();
        });
        it('should find NTLM in array', function(done) {
            var findNTLM = HttpsProxyAgent.__get__('findNTLM');
            assert.ok(findNTLM(['Negotiate', 'NTLM']), "included in vals");
            assert.equal(findNTLM(['Negotiate']), false, "not included in vals");
            done();
        });
        it('should recoginze NTLM negotiation request', function(done) {
            var isNTLMNegotiation = HttpsProxyAgent.__get__('isNTLMNegotiation');
            var message = { headers:
                {'proxy-authenticate': ['Negotiate', 'NTLM']}
            };
            assert.ok(isNTLMNegotiation(message));
            done();
        });
        it('should receive 200 on successfull authentication connect', function (done) {
            // set a proxy authentication function for this test

            var proxyUri = process.env.HTTP_PROXY || process.env.http_proxy || 'http://127.0.0.1:' + proxyPort;
            var agent = new HttpsProxyAgent(proxyUri);

            var opts = {};
            // `host` and `port` don't really matter since the proxy will reject anyways
            opts.host = '127.0.0.1';
            opts.port = 80;
            opts.agent = agent;

            var req = http.get(opts, function (res) {
                assert.equal(200, res.statusCode);
                done();
            });
        }).timeout(100);

    });

});
