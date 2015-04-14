
"use strict";

var util = require( 'util' );
var EventEmitter = require( 'events' ).EventEmitter;
var log = require( 'logg' ).getLogger( 'dtls.DtlsSocket' );
var crypto = require( 'crypto' );
var constants = require( 'constants' );

var dtls = require( './dtls' );
var SecurityParameterContainer = require( './SecurityParameterContainer' );
var DtlsRecordLayer = require( './DtlsRecordLayer' );
var ServerHandshakeHandler = require( './ServerHandshakeHandler' );
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
    this.recordLayer = new DtlsRecordLayer( dgram, rinfo, this.parameters );
    this.handshakeHandler = new ServerHandshakeHandler(
        this.parameters, this.keyContext );

    this.handshakeHandler.onSend = function( packets ) {
        this.recordLayer.send( packets );
    }.bind( this );

    this.handshakeHandler.onHandshake = function() {
        this.emit( 'secureConnection', this );
    }.bind( this );
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

DtlsSocket.prototype.process_handshake = function( message ) {
    this.handshakeHandler.process( message );
};

DtlsSocket.prototype.process_changeCipherSpec = function( message ) {
    // Record layer does the work here.
    log.info( 'Changed Cipher Spec' );
};

DtlsSocket.prototype.process_applicationData = function( message ) {
    log.info( 'Received application data: ', message.fragment );
    this.emit( 'message', message.fragment );
};

module.exports = DtlsSocket;
