
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.DtlsSession' );
var crypto = require( 'crypto' );

var dtls = require( './dtls' );
var DtlsRecordLayer = require( './DtlsRecordLayer' );

var DtlsPlaintext = require( './packets/DtlsPlaintext' );
var DtlsHandshake = require( './packets/DtlsHandshake' );
var DtlsServerHello = require( './packets/DtlsServerHello' );
var DtlsClientHello = require( './packets/DtlsClientHello' );
var DtlsExtension = require( './packets/DtlsExtension' );
var DtlsHelloVerifyRequest = require( './packets/DtlsHelloVerifyRequest' );
var DtlsProtocolVersion = require( './packets/DtlsProtocolVersion' );
var DtlsRandom = require( './packets/DtlsRandom' );
var HandshakeBuilder = require( './HandshakeBuilder' );

var SessionState = {
    uninitialized: 0,
    sendHello: 1,
};

var DtlsSession = function( dgram, rinfo ) {
    log.info( 'New session' );

    this.dgram = dgram;
    this.rinfo = rinfo;

    this.state = SessionState.uninitialized;
    this.recordLayer = new DtlsRecordLayer( dgram, rinfo );

    this.handshakeBuilder = new HandshakeBuilder();

    this.sequence = 0;
    this.messageSeq = 0;
};

DtlsSession.prototype.serverVersion = new DtlsProtocolVersion({
    major: ~1,
    minor: ~0
});

DtlsSession.prototype.handle = function( packet ) {

    log.fine( 'Incoming packet; length:', packet.length );
    var message = this.recordLayer.handlePacket( packet );

    var msgType = dtls.MessageTypeName[ message.type ];
    var handler = this[ 'process_' + msgType ];

    if( !handler )
        return log.error( 'Handler not found for', msgType, 'message' );

    handler.call( this, message );
};

DtlsSession.prototype.changeState = function( state ) {

    log.info( 'DTLS session state changed to', state );
    this.state = state;

    if( this.invokeAction( this.state ) ) {
        // TODO: Launch timer.
    }
};

DtlsSession.prototype.process_handshake = function( message ) {

    // Enqueue the current handshake.
    var newHandshake = new DtlsHandshake( message.fragment );
    var newHandshakeName = dtls.HandshakeTypeName[ newHandshake.msgType ];
    log.info( 'Received handshake fragment; sequence:',
        newHandshake.messageSeq + ':' + newHandshakeName );
    this.handshakeBuilder.add( newHandshake );

    // Process available defragmented handshakes.
    var handshake = this.handshakeBuilder.next();
    while( handshake ) {
        var handshakeName = dtls.HandshakeTypeName[ handshake.msgType ];

        log.info( 'Processing handshake:',
            handshake.messageSeq + ':' + handshakeName );
        this[ 'process_handshake_' + handshakeName ]( handshake );

        handshake = this.handshakeBuilder.next();
    }
};

DtlsSession.prototype.process_handshake_clientHello = function( handshake ) {

    var clientHello = new DtlsClientHello( handshake.body );

    if( clientHello.cookie.length === 0 ) {

        this.cookie = crypto.pseudoRandomBytes( 16 );
        var cookieVerify = new DtlsHelloVerifyRequest({
            serverVersion: this.serverVersion,
            cookie: this.cookie
        });

        var handshakes = this.handshakeBuilder.createHandshakes( cookieVerify );

        log.fine( 'ClientHello without cookie. Requesting verify.' );
        this.recordLayer.send( handshakes );

    } else {
        log.fine( 'ClientHello received.' );
        this.changeState( SessionState.sendHello );
    }
};

DtlsSession.prototype.invokeAction = function( state ) {

    if( !this.actions[ state ] )
        return false;

    this.actions[ state ].call( this );
};

DtlsSession.prototype.actions = {};
DtlsSession.prototype.actions[ SessionState.sendHello ] = function() {

    var serverHello = new DtlsServerHello({
        serverVersion: this.serverVersion,
        random: new DtlsRandom(),
        sessionId: new Buffer(0),
        cipherSuite: 0x0033,
        compressionMethod: 0,
        extensions: [
            new DtlsExtension({
                extensionType: 0x000f,
                extensionData: new Buffer([ 1 ])
            })
        ]
    });

    log.info( 'Sending ServerHello' );
    var handshakes = this.handshakeBuilder.createHandshakes( serverHello );
    this.recordLayer.send( handshakes );

};

    /*
    var payload, type;
    if( clientHello.cookie.length === 0 ) {

        var cookieVerify = new DtlsHelloVerifyRequest();
        cookieVerify.serverVersion = { major: 0xfe, minor: 0xff };
        cookieVerify.cookie = new Buffer([ 0x01, 0x02, 0x03, 0x04 ]);

        payload = cookieVerify.toBuffer();
        type = 3;

    } else {

        var serverHello = new DtlsServerHello();
        serverHello.serverVersion = { major: 0xfe, minor: 0xff };
        serverHello.random = new DtlsRandom();
        serverHello.random.generate();
        serverHello.sessionId = new Buffer(0);
        serverHello.cipherSuite = 0x0033;
        serverHello.compressionMethod = 0;
        serverHello.extensions = [ new DtlsExtension() ];
        serverHello.extensions[0].extensionType = 0x000f;
        serverHello.extensions[0].extensionData = new Buffer([ 0x01 ]);

        type = dtls.HandshakeType.serverHello;
        payload = serverHello.toBuffer();
    }

    var responseHandshake = new DtlsHandshake();
    responseHandshake.msgType = type;
    responseHandshake.messageSeq = this.messageSeq++;
    responseHandshake.length = payload.length;
    responseHandshake.fragmentOffset = 0;
    responseHandshake.body = payload;

    var handshakeBuffer = responseHandshake.toBuffer();

    var plaintext = new DtlsPlaintext();
    plaintext.type = dtls.MessageType.handshake;
    plaintext.version = { major: 0xfe, minor: 0xff };
    plaintext.epoch = 0;
    plaintext.sequenceNumber = new Buffer([ 0x00, 0x00, 0x00, 0x00, 0x00, this.sequence++ ]);
    plaintext.fragment = handshakeBuffer;

    var response = plaintext.toBuffer();
    this.dgram.send(
        response,
        0, response.length,
        this.rinfo.port, this.rinfo.address,
        function( err ) {

            if( err )
                console.log( err );
    });
};
*/

module.exports = DtlsSession;
