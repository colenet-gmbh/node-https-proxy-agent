/**
 * Module dependencies.
 */

var net = require('net');
var tls = require('tls');
var url = require('url');
var httpMessageParser = require('http-message-parser-ts');
var Agent = require('agent-base');
var inherits = require('util').inherits;
var debug = require('debug')('https-proxy-agent');

/**
 * Module exports.
 */

module.exports = HttpsProxyAgent;

/**
 * The `HttpsProxyAgent` implements an HTTP Agent subclass that connects to the
 * specified "HTTP(s) proxy server" in order to proxy HTTPS requests.
 *
 * @api public
 */

function HttpsProxyAgent(opts, sspi) {
  if (!(this instanceof HttpsProxyAgent)) return new HttpsProxyAgent(opts, sspi);
  if ('string' == typeof opts) opts = url.parse(opts);
  if (!opts)
    throw new Error(
      'an HTTP(S) proxy server `host` and `port` must be specified!'
    );
  debug('creating new HttpsProxyAgent instance: %o', opts);
  Agent.call(this, opts);

  var proxy = Object.assign({}, opts);

  // if `true`, then connect to the proxy server over TLS. defaults to `false`.
  this.secureProxy = proxy.protocol ? /^https:?$/i.test(proxy.protocol) : false;

  // prefer `hostname` over `host`, and set the `port` if needed
  proxy.host = proxy.hostname || proxy.host;
  proxy.port = +proxy.port || (this.secureProxy ? 443 : 80);

  // ALPN is supported by Node.js >= v5.
  // attempt to negotiate http/1.1 for proxy servers that support http/2
  if (this.secureProxy && !('ALPNProtocols' in proxy)) {
    proxy.ALPNProtocols = ['http 1.1']
  }

  if (proxy.host && proxy.path) {
    // if both a `host` and `path` are specified then it's most likely the
    // result of a `url.parse()` call... we need to remove the `path` portion so
    // that `net.connect()` doesn't attempt to open that as a unix socket file.
    delete proxy.path;
    delete proxy.pathname;
  }

  this.proxy = proxy;
  this.sspi = sspi;
}
inherits(HttpsProxyAgent, Agent);

/**
 * Called when the node-core HTTP client library is creating a new HTTP request.
 *
 * @api public
 */

HttpsProxyAgent.prototype.callback = function connect(req, opts, fn) {
  var proxy = this.proxy;
  var sspi  = this.sspi;

  // create a socket connection to the proxy server
  var socket;
  if (this.secureProxy) {
    socket = tls.connect(proxy);
  } else {
    socket = net.connect(proxy);
  }

  // we need to buffer any HTTP traffic that happens with the proxy before we get
  // the CONNECT response, so that if the response is anything other than an "200"
  // response code, then we can re-play the "data" events on the socket once the
  // HTTP parser is hooked up...
  var buffers = [];
  var buffersLength = 0;

  function read() {
    var b = socket.read();
    if (b) ondata(b);
    else socket.once('readable', read);
  }

  function cleanup() {
    socket.removeListener('data', ondata);
    socket.removeListener('end', onend);
    socket.removeListener('error', onerror);
    socket.removeListener('close', onclose);
    socket.removeListener('readable', read);
  }

  function onclose(err) {
    debug('onclose had error %o', err);
  }

  function onend() {
    debug('onend');
  }

  function onerror(err) {
    cleanup();
    fn(err);
  }

  function ondata(b) {
    buffers.push(b);
    buffersLength += b.length;
    var buffered = Buffer.concat(buffers, buffersLength);
    var str = buffered.toString('ascii');

    if (!~str.indexOf('\r\n\r\n')) {
      // keep buffering
      console.info('have not received end of HTTP headers yet...');
      if (socket.read) {
        read();
      } else {
        socket.once('data', ondata);
      }
      return;
    }

    console.info('have  received end of HTTP headers : %o', str);
    var parser = new httpMessageParser.HttpMessageParser();
    const response = parser.parseResponse(str);

    if (200 == response.statusCode) {
      // 200 Connected status code!
      console.info('<<<< Connection established');
      var sock = socket;

      // nullify the buffered data since we won't be needing it
      buffers = buffered = null;

      if (opts.secureEndpoint) {
        // since the proxy is connecting to an SSL server, we have
        // to upgrade this socket connection to an SSL connection
        debug(
          'upgrading proxy-connected socket to TLS connection: %o',
          opts.host
        );
        opts.socket = socket;
        opts.servername = opts.servername || opts.host;
        opts.host = null;
        opts.hostname = null;
        opts.port = null;
        sock = tls.connect(opts);
      }

      cleanup();
      fn(null, sock);
    }
    else if (407 == response.statusCode) {
      if (isNTLMNegotiation(response) &&  sspi) {
          console.info('<<<<<<< ntlm authentication required AND sspi module set');
        // we need to connect with new socket and send type1 and type3 messages
          var challenge = extractChallenge(response);
          var nextRound = null;
          if (challenge.length === 0) {
            nextRound = sspi.generate_type1_message();
          }
          else {
            var type_2 = Buffer.from(challenge, 'base64');
            nextRound = sspi.generate_type3_message(type_2);
          }
          nextRound.toString('base64');
          proxy.ntlmChallenge = nextRound.toString('base64');
          var msg = createConnectRequest(opts, proxy, {});
          socket.write(msg);
      }
      else {
        cleanup();
        buffers = buffered;
        req.once('socket', onsocket);
        fn(null, socket);
      }
    }
    else {
      // some other status code that's not 200... need to re-play the HTTP header
      // "data" events onto the socket once the HTTP machinery is attached so that
      // the user can parse and handle the error status code
      cleanup();

      // save a reference to the concat'd Buffer for the `onsocket` callback
      buffers = buffered;

      // need to wait for the "socket" event to re-play the "data" events
      req.once('socket', onsocket);
      fn(null, socket);
    }
  }

  function onsocket(socket) {
    // replay the "buffers" Buffer onto the `socket`, since at this point
    // the HTTP module machinery has been hooked up for the user
    if ('function' == typeof socket.ondata) {
      // node <= v0.11.3, the `ondata` function is set on the socket
      socket.ondata(buffers, 0, buffers.length);
    } else if (socket.listeners('data').length > 0) {
      // node > v0.11.3, the "data" event is listened for directly
      socket.emit('data', buffers);
    } else {
      // never?
      throw new Error('should not happen...');
    }

    // nullify the cached Buffer instance
    buffers = null;
  }

  socket.on('error', onerror);
  socket.on('close', onclose);
  socket.on('end', onend);

  if (socket.read) {
    read();
  } else {
    socket.once('data', ondata);
  }

  var msg = createConnectRequest(opts, proxy, {'Connection': 'close'} );
  socket.write(msg);
};

function createConnectRequest(opts, proxy, additionalHeaders) {
  function crlf() {return '\r\n'}

  var hostname = opts.host + ':' + opts.port;
  var msg = 'CONNECT ' + hostname + ' HTTP/1.1' + crlf();

  var headers = Object.assign({}, proxy.headers);
  if (proxy.auth) {
      headers['Proxy-Authorization'] =
          'Basic ' + new Buffer(proxy.auth).toString('base64');
  }
  console.info("<<<< proxy %o", proxy)
  if (proxy.ntlmChallenge) {
      headers['Proxy-Authorization'] =
          'NTLM ' + proxy.ntlmChallenge;
  }
  var host = opts.host;
  if (!isDefaultPort(opts.port, opts.secureEndpoint)) {
      host += ':' + opts.port;
  }
  headers['Host'] = host;

  Object.keys(headers).forEach(function(name) {
      msg += name + ': ' + headers[name] + crlf();
  });
  Object.keys(additionalHeaders).forEach(function(name) {
      msg += name + ': ' + additionalHeaders[name] + crlf();
  });
  msg += crlf();
  return msg;
}

function findNTLM(val) {
  return val.includes('NTLM');
}


function isNTLMNegotiation(response) {
  const headers = response.headers;
  if (headers) {
    const proxyAuth = headers['proxy-authenticate'];
    if (proxyAuth) {
      const ntlm = proxyAuth.find(findNTLM);
      var result = (ntlm !== undefined);
      return result;
    }
    else {
        return false;
    }
  }
  return false;
}

function extractChallenge(response) {
    const headers = response.headers;
    var result = '';
    if (headers) {
        const proxyAuth = headers['proxy-authenticate'];
        if (proxyAuth) {
            const ntlm = proxyAuth.find(findNTLM);
            const parts = ntlm.split(' ');
            if (parts.length > 1) {
                result = parts[1];
            }
        }
    }
    return result;
}

function isDefaultPort(port, secure) {
  return Boolean((!secure && port === 80) || (secure && port === 443));
}
