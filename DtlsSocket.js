
"use strict";

var util = require( 'util' );
var EventEmitter = require( 'events' ).EventEmitter;
var log = require( 'logg' ).getLogger( 'dtls.DtlsSocket' );
var crypto = require( 'crypto' );
var constants = require( 'constants' );

var dtls = require( './dtls' );
var prf = require( './prf' );
var SecurityParameterContainer = require( './SecurityParameterContainer' );
var DtlsRecordLayer = require( './DtlsRecordLayer' );
var HandshakeBuilder = require( './HandshakeBuilder' );
var CipherInfo = require( './CipherInfo' );

var DtlsHandshake = require( './packets/DtlsHandshake' );

var DtlsClientHello = require( './packets/DtlsClientHello' );
var DtlsHelloVerifyRequest = require( './packets/DtlsHelloVerifyRequest' );
var DtlsServerHello = require( './packets/DtlsServerHello' );
var DtlsCertificate = require( './packets/DtlsCertificate' );
var DtlsServerHelloDone = require( './packets/DtlsServerHelloDone' );
var DtlsClientKeyExchange_rsa = require( './packets/DtlsClientKeyExchange_rsa' );
var DtlsPreMasterSecret = require( './packets/DtlsPreMasterSecret' );
var DtlsChangeCipherSpec = require( './packets/DtlsChangeCipherSpec' );
var DtlsFinished = require( './packets/DtlsFinished' );

var DtlsExtension = require( './packets/DtlsExtension' );
var DtlsProtocolVersion = require( './packets/DtlsProtocolVersion' );
var DtlsRandom = require( './packets/DtlsRandom' );

var SocketState = {
    uninitialized: 0,
    sendHello: 1,
    handshakeDone: 2,
    clientFinished: 3,
};

var DtlsSocket = function( dgram, rinfo, keyContext ) {
    log.info( 'New session' );

    this.dgram = dgram;
    this.rinfo = rinfo;
    this.keyContext = keyContext;

    this.parameters = new SecurityParameterContainer();
    this.state = SocketState.uninitialized;
    this.recordLayer = new DtlsRecordLayer( dgram, rinfo, this.parameters );

    this.handshakeBuilder = new HandshakeBuilder();
    this.handshakeMessages = [];

    this.sequence = 0;
    this.messageSeq = 0;
};
util.inherits( DtlsSocket, EventEmitter );

DtlsSocket.prototype.send = function( buffer, offset, length, callback ) {

    // Slice the buffer if we have offset specified and wrap it into a packet
    // structure that holds the message type as well.
    if( offset )
        buffer = buffer.slice( offset, offset + length );

    var lengthBuffer = new Buffer(2);
    lengthBuffer.writeUInt16BE( buffer.length );

    var packet = {
        type: dtls.MessageType.applicationData,
        buffer: Buffer.concat([ buffer ])
    };

    this.recordLayer.send( packet, callback );
};

DtlsSocket.prototype.handle = function( buffer ) {
    var self = this;

    log.fine( 'Incoming packet; length:', buffer.length );
    this.recordLayer.getPackets( buffer, function( packet ) {

        var msgType = dtls.MessageTypeName[ packet.type ];
        var handler = self[ 'process_' + msgType ];

        if( !handler )
            return log.error( 'Handler not found for', msgType, 'message' );

        handler.call( self, packet );
    });
};

DtlsSocket.prototype.changeState = function( state ) {

    log.info( 'DTLS session state changed to', state );
    this.state = state;

    if( this.invokeAction( this.state ) ) {
        // TODO: Launch timer.
    }
};

DtlsSocket.prototype.process_handshake = function( message ) {

    // Enqueue the current handshake.
    var newHandshake = new DtlsHandshake( message.fragment );
    var newHandshakeName = dtls.HandshakeTypeName[ newHandshake.msgType ];
    log.info( 'Received handshake fragment; sequence:',
        newHandshake.messageSeq + ':' + newHandshakeName );
    this.handshakeBuilder.add( newHandshake );

    // Process available defragmented handshakes.
    var handshake = this.handshakeBuilder.next();
    while( handshake ) {
        this.parameters.pending.digestHandshake( handshake.getBuffer() );
        var handshakeName = dtls.HandshakeTypeName[ handshake.msgType ];

        var handler = this[ 'process_handshake_' + handshakeName ];
        if( handler ) {
            log.info( 'Processing handshake:',
                handshake.messageSeq + ':' + handshakeName );
            this[ 'process_handshake_' + handshakeName ]( handshake, message );
        } else {
            log.error( 'Handshake handler not found for ' + handshakeName + ' message' );
        }

        handshake = this.handshakeBuilder.next();
    }
};

DtlsSocket.prototype.process_changeCipherSpec = function( message ) {
    // Record layer does the work here.
    log.info( 'Changed Cipher Spec' );
};

DtlsSocket.prototype.process_applicationData = function( message ) {
    log.info( 'Received application data: ', message.fragment );
    this.emit( 'message', message.fragment );
};

DtlsSocket.prototype.process_handshake_clientHello = function( handshake, message ) {

    var clientHello = new DtlsClientHello( handshake.body );

    if( clientHello.cookie.length === 0 ) {

        this.cookie = crypto.pseudoRandomBytes( 16 );
        var cookieVerify = new DtlsHelloVerifyRequest({
            serverVersion: clientHello.clientVersion,
            cookie: this.cookie
        });

        var handshakes = this.handshakeBuilder.createHandshakes( cookieVerify );

        log.fine( 'ClientHello without cookie. Requesting verify.' );
        this.recordLayer.send( handshakes );

    } else {
        log.fine( 'ClientHello received. Client version:', ~clientHello.clientVersion.major + '.' + ~clientHello.clientVersion.minor );
        this.parameters.get( message ).version = clientHello.clientVersion;
        this.parameters.pending.clientRandom = clientHello.random.getBytes();
        this.parameters.pending.version = clientHello.clientVersion;

        // Reset the handshakeMessages when we receive a proper ClientHello.
        // We should ignore any ClientHello/VerifyRequest pairs.
        this.parameters.pending.resetHandshakeDigest();
        this.parameters.pending.digestHandshake( handshake.getBuffer() );
        this.changeState( SocketState.sendHello );
    }
};

DtlsSocket.prototype.process_handshake_clientKeyExchange = function( handshake ) {

    var clientKeyExchange = new DtlsClientKeyExchange_rsa( handshake.body );

    var preMasterSecret = crypto.privateDecrypt({
            key: this.keyContext.key,
            padding: constants.RSA_PKCS1_PADDING
        }, clientKeyExchange.exchangeKeys );

    //preMasterSecret = new DtlsPreMasterSecret( preMasterSecret );

    this.parameters.pending.preMasterKey = preMasterSecret;
    this.parameters.pending.masterKey = prf( this.parameters.pending.version )(
        preMasterSecret,
        "master secret", 
        Buffer.concat([
            this.parameters.pending.clientRandom,
            this.parameters.pending.serverRandom ]), 48 );

    //this.changeState( SocketState.handshakeDone );
};

DtlsSocket.prototype.process_handshake_finished = function( handshake, message ) {

    var finished = new DtlsFinished( handshake.body );

    var parameters = this.parameters.get( message );
    var prf_func = prf( message.version );

    var handshakeMessages = Buffer.concat( parameters.handshakeMessages );

    var expected = prf_func(
            parameters.masterKey,
            "client finished",
            parameters.getHandshakeDigest(),
            finished.verifyData.length
        );

    if( !finished.verifyData.equals( expected ) ) {
        log.warn( 'Finished digest does not match. Expected:',
            expected,
            'Actual:',
            finished.verifyData );
        return;
    }

    // process_handshake takes care of adding all handshake messages to the
    // pending SecurityParameters digest. However this message is still part of
    // the previous handshake so we need to add it manually to that digest.
    parameters.digestHandshake( handshake.getBuffer() );

    this.changeState( SocketState.clientFinished );
};

DtlsSocket.prototype.invokeAction = function( state ) {

    if( !this.actions[ state ] )
        return false;

    this.actions[ state ].call( this );
};

DtlsSocket.prototype.actions = {};
DtlsSocket.prototype.actions[ SocketState.sendHello ] = function() {

    var cipher = CipherInfo.TLS_RSA_WITH_AES_128_CBC_SHA;

    var serverHello = new DtlsServerHello({
        serverVersion: this.parameters.pending.version,
        random: new DtlsRandom(),
        sessionId: new Buffer(0),
        cipherSuite: cipher.id,
        compressionMethod: 0,
        extensions: [
            new DtlsExtension({
                extensionType: 0x000f,
                extensionData: new Buffer([ 1 ])
            })
        ]
    });

    this.parameters.pending.serverRandom = serverHello.random.getBytes();
    this.parameters.pending.setFrom( cipher );

    var certificate = new DtlsCertificate({
        certificateList: [ this.keyContext.certificate ]
    });

    var helloDone = new DtlsServerHelloDone();

    log.info( 'Sending ServerHello, Certificate, HelloDone' );
    var handshakes = this.handshakeBuilder.createHandshakes([
        serverHello,
        certificate,
        helloDone
    ]);

    handshakes = handshakes.map( function(h) { return h.getBuffer(); });
    this.parameters.pending.digestHandshake( handshakes );

    var packets = this.handshakeBuilder.fragmentHandshakes( handshakes );
    var messages = this.recordLayer.send( packets );
};

DtlsSocket.prototype.actions[ SocketState.handshakeDone ] = function() {

};

DtlsSocket.prototype.actions[ SocketState.clientFinished ] = function() {

    var changeCipherSpec = new DtlsChangeCipherSpec({ value: 1 });

    // Get the parameters for the next epoch.
    // The changeCipherSpec will be sent before the Finished
    // message, so we need sendEpoch + 1.
    var parameters = this.parameters.getCurrent( 
        this.recordLayer.sendEpoch + 1 );
    var prf_func = prf( parameters.version );

    var finished = new DtlsFinished({
        verifyData: prf_func(
            parameters.masterKey,
            "server finished",
            parameters.getHandshakeDigest(), 12
        )});

    var handshakes = this.handshakeBuilder.createHandshakes([ finished ]);
    handshakes = this.handshakeBuilder.fragmentHandshakes( handshakes );
    handshakes.unshift( changeCipherSpec );

    log.info( 'Verify data:', finished.verifyData );
    log.info( 'Sending ChangeCipherSpec, Finished' );

    var messages = this.recordLayer.send( handshakes, function() {
        this.emit( 'secureConnect', this );
    }.bind( this ));
};

module.exports = DtlsSocket;
