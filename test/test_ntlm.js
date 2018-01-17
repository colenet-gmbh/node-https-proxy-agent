
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
var sinon = require('sinon');
var should = require('should');
var HttpsProxyAgent = rewire('../index.js');

var SSPIMock = {
    generate_type1_message: function() {
        return Buffer.from('testround1');
    },
    generate_type2_message: function(buffer) {
        return Buffer.from('testround2');
    },
    generate_type3_message: function(buffer) {
        return Buffer.from('testround3');
    },
}

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
        it('should recoginze NTLM negotiation request', function(done) {
            var isNTLMNegotiation = HttpsProxyAgent.__get__('isNTLMNegotiation');
            var message = { headers:
                {'proxy-authenticate': ['Negotiate', 'NTLM 12312']}
            };
            assert.ok(isNTLMNegotiation(message));
            done();
        });
        it('should extractChallenge from NTLM', function(done) {
            var extractChallenge = HttpsProxyAgent.__get__('extractChallenge');
            var message = { headers:
                    {'proxy-authenticate': ['Negotiate', 'NTLM 123123']}
            };
            var challenge = extractChallenge(message);
            assert.equal(challenge, '123123');
            done();
        });
        it('should extractChallenge from NTLM for firstRound as ""', function(done) {
            var extractChallenge = HttpsProxyAgent.__get__('extractChallenge');
            var message = { headers:
                    {'proxy-authenticate': ['Negotiate', 'NTLM']}
            };
            var challenge = extractChallenge(message);
            assert.equal(challenge, '');
            done();
        });
        it('should generate a CONNECT HTTP request', function () {
            var createConnectRequest = HttpsProxyAgent.__get__('createConnectRequest');
            var additionHeaders = {'proxy-authenticate': 'NTLM 123123'};
            var opts = {
                host: 'test.com',
                port: 443,
                secureEndpoint: true,
            };
            var proxy = {
                headers: {'Proxy-Connection': 'keep-alive'}
            }
            var msg = createConnectRequest(opts, proxy, additionHeaders);
            var expectedMsg = 'CONNECT test.com:443 HTTP/1.1\r\n';
            expectedMsg += 'Proxy-Connection: keep-alive\r\n';
            expectedMsg += 'Host: test.com\r\n';
            expectedMsg += 'proxy-authenticate: NTLM 123123\r\n';
            expectedMsg += '\r\n';
            assert.equal(msg, expectedMsg);
        });
        it('should receive 200 on successfull authentication connect', function (done) {
            // set a proxy authentication function for this test
            var firstRoundSpy = sinon.spy(SSPIMock, 'generate_type1_message');
            var secondRoundSpy = sinon.spy(SSPIMock, 'generate_type3_message');
            var proxyUri = process.env.HTTP_PROXY || process.env.http_proxy || 'http://127.0.0.1:' + proxyPort;
            var proxyOpts = url.parse(proxyUri);
            proxyOpts.ntlmChallenge = 'round1';
            console.info("<<< proxyOpts %o", proxyOpts);
            var agent = new HttpsProxyAgent(proxyOpts, SSPIMock);

            var opts = {};
            // `host` and `port` don't really matter since the proxy will reject anyways
            opts.host = '127.0.0.1';
            opts.port = 80;
            opts.agent = agent;
            var req = http.get(opts, function (res) {
                sinon.assert.called(firstRoundSpy);
                sinon.assert.calledOnce(secondRoundSpy);
                assert.ok(firstRoundSpy.calledBefore(secondRoundSpy));
                assert.equal(200, res.statusCode);
                done();
            });
        }).timeout(2000);

    });

});
