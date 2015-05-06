
node-dtls
=========
### DTLS implementation in JavaScript (Work in progress)

[![Travis build](https://travis-ci.org/Rantanen/node-dtls.svg?branch=master)](https://travis-ci.org/Rantanen/node-dtls)
[![Test Coverage](https://codeclimate.com/github/Rantanen/node-dtls/badges/coverage.svg)](https://codeclimate.com/github/Rantanen/node-dtls/coverage)

Datagram Transport Layer Security (DTLS) Protocol implementation for Node.js
written in JavaScript.

While Node.js still lacks support for DTLS protocol, this library attempts to
fix the issue. This is in no way a security implementation as it's main goal is
to allow using protocols that _require_ DTLS. While the library implements the
proper DTLS encryption and validation, there has been no effort to protect it
against well known TLS attacks.

#### Example

##### Server

```javascript
var dtls = require( 'dtls' );
var fs = require( 'fs' );

var pem = fs.readFileSync( 'server.pem' );

var server = dtls.createServer({ type: 'udp4', key: pem, cert: pem });
server.bind( 4433 );

server.on( 'secureConnection', function( socket ) {

  console.log( 'New connection from ' +
    [ socket.rinfo.address, socket.rinfo.port ].join(':') );

  socket.on( 'message', function( message ) {
    
    // Echo the message back
    socket.send( message );
  });
});
```

##### Client

```javascript
var dtls = require( '../' );

dtls.setLogLevel( dtls.logLevel.FINE );

var client = dtls.connect( 4433, 'example.org', 'udp4', function() {
    client.send( new Buffer( 'foo\n' ) );
});

client.on( 'message', function( msg ) {
    console.log( msg );
});
```

#### Current state


- [x] DTLS 1.2 handshake in server role
- [x] DTLS 1.2 handshake in client role
  - Still some problems when it comes to receiving messages. Not very confident.
- [x] Handle application data
- [x] Proper API to handle sessions/messages outside the node-dtls internals.
- [ ] DTLS 1.0 handshake in server role
  - There shouldn't be _too_ many changes. Main one is propably the PRF hash.
- [ ] Handle renegotiation
- [ ] Robustness
  - [x] Handshake reassembly/buffering/reordering
  - [x] Retransmission
  - [ ] Handle alert-messages
  - [ ] Validate handshake state and expected messages

## API

#### dtls.setLogLevel( level )

- `level` - [logg](https://github.com/dpup/node-logg) log level. For convenience possible log levels are also available in `dtls.logLevel.*`

Sets the global node-dtls logging level.

node-dtls uses /logg/ for logging and tracing various dtls events. This function can be used to alter the amount of information that is logged during the DTLS handshake/session. In future logging will most likely be disabled by default, but for now the default log level (FINE) is quite verbose.

-----

#### dtls.createServer(options[, callback])

- `options` - Server options, see below.
- `callback` - Optional callback registered to the `secureConnect` event.

Creates a `dtls.DtlsServer`.

Mimics the Node.js [tls.createServer](https://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener) function. Although given DTLS is a datagram protocol, the actual network object is created with [dgram.createSocket()](https://nodejs.org/api/dgram.html#dgram_dgram_createsocket_options_callback).

`options` object is a rough combination of the option objects of `tls.createServer()` and `dgram.createSocket()`. DTLS-specific options are parsed by the `dtls.DtlsServer` and the dgram-options are passed directly to `dgram.createSocket()`.

- `type` - _Required._ `dgram` socket type. Passed to `dgram.createSocket()`.
- `key` - _Required._ The server private key in PEM format.
- `cert` - _Required._ The server certificate in PEM format.

##### Example

```javascript
var dtls = require( 'dtls' );
var fs = require( 'fs' );
    
var pem = fs.readFileSync( 'server.pem' );
    
var server = dtls.createServer({ type: 'udp4', cert: pem, key: pem });
server.bind( 4433 );
    
server.on( 'secureConnection', function( socket ) {
  console.log( 'New secure connection: ' +
    [ socket.rinfo.address, socket.rinfo.port ].join( ':' ) );
});
```

The server.pem certificate can be created with

    openssl req -x509 -nodes -newkey rsa:2048 -keyout server.pem -out server.pem

-----

#### dtls.connect( port, address, type, callback )

- `port` - Remote port to connect to.
- `address` - Remote address to connect to.
- `type` - Datagram socket type: `udp4` or `udp6`. Ssee [`dgram`](https://nodejs.org/api/dgram.html) for full explanation.
- `callback` - Callback for when the handshake is ready.

Initiates a connection to a remote server and returns the `dtls.DtlsSocket`.

##### Example

```javascript
var dtls = require( 'dtls' );

var client = dtls.connect( 4433, 'example.org', 'udp4', function() {
    client.send( new Buffer( 'foo\n' ) );
});

client.on( 'message', function( msg ) {
    console.log( msg );
});
```

-----

### Class: dtls.DtlsServer

Server accepting DTLS connections. Created with `dtls.createServer`

-----

#### Event: 'secureConnection'

- `socket` - dtls.DtlsSocket

Emitted after the `DtlsSocket` has finished handshaking a connection and is ready for use.

-----

#### server.bind();

- `port` - UDP port to listen to. This is passed over to `socket.bind()` of the underlying `dgram.Socket`

Starts listening to the defined port. Delegated to `dgram.Socket#bind()`

-----
-----

### Class: dtls.DtlsSocket

A single DTLS session between a local and remote endpoints. Acquired through the `server::secureConnection` event.

----

#### Event: 'secureConnect'

Emitted after the `DtlsSocket` has finished handshaking a connection.

This method is emitted after the server sends the `Finished` handshake message. As datagram protocols aren't reliable transports, the handshake might still be in progress if that last handshake message was lost. It is recommended that the client initiates the actual application communication as the client gets confirmation on when the handshake has been completed.

_Note:_ that usually it is impossible to catch this event as it is raised before the user has a reference to the socket. Use `server::secureConnection` event instead.

-----

#### Event: 'message'

- `buffer` - Application data within a [`Buffer`](https://nodejs.org/api/buffer.html#buffer_class_buffer).

Emitted when the socket has received and decrypted application data from the remote endpoint.

##### Example

```javascript
var server = dtls.createServer({
    type: 'udp4',
    key: pem,
    cert: pem
});
server.bind( 4433 );

server.on( 'secureConnection', function( socket ) {
  socket.on( 'message', function( message ) {
    console.log( 'In: ' + message.toString( 'ascii' ) );
  });
});
```

-----

#### socket.send( buffer[, offset][, length][, callback] )

- `buffer` - `Buffer` object to send.
- `offset` - Offset in the buffer where the message starts. Optional.
- `length` - Number of bytes in the message. Optional.
- `calback` - called when the message has been sent. Optional.

Sends application data to the remote endpoint.

##### Example

```javascript
var server = dtls.createServer({
    type: 'udp4',
    key: pem,
    cert: pem
});
server.bind( 4433 );

server.on( 'secureConnection', function( socket ) {
  socket.send( new Buffer( 'Hello!\n', 'ascii' ) );
});
```

-----

## References

[Datagram Transport Layer Security Version 1.2, RFC 6347]
(https://tools.ietf.org/html/rfc6347)

[The Transport Layer Security (TLS) Protocol Version 1.2, RFC 5246]
(https://tools.ietf.org/html/rfc5246)
