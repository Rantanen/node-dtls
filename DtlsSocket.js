
"use strict";

var util = require( 'util' );
var EventEmitter = require( 'events' ).EventEmitter;
var log = require( 'logg' ).getLogger( 'dtls.DtlsSocket' );
var crypto = require( 'crypto' );
var constants = require( 'constants' );
var dgram = require( 'dgram' );

var dtls = require( './dtls' );
var SecurityParameterContainer = require( './SecurityParameterContainer' );
var DtlsRecordLayer = require( './DtlsRecordLayer' );
var ServerHandshakeHandler = require( './ServerHandshakeHandler' );
var ClientHandshakeHandler = require( './ClientHandshakeHandler' );
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

var DtlsSocket = function( dgram, rinfo, keyContext, isServer ) {
    log.info( 'New session' );

    this.dgram = dgram;
    this.rinfo = rinfo;
    this.keyContext = keyContext;
    this.isServer = isServer;

    this.parameters = new SecurityParameterContainer();
    this.recordLayer = new DtlsRecordLayer( dgram, rinfo, this.parameters );
    this.handshakeHandler = isServer
        ? new ServerHandshakeHandler( this.parameters, this.keyContext, rinfo )
        : new ClientHandshakeHandler( this.parameters );

    this.handshakeHandler.onSend = function( packets, callback ) {
        this.recordLayer.send( packets, callback );
    }.bind( this );

    this.handshakeHandler.onHandshake = function() {
        log.info( 'Handshake done' );
        this.emit( 'secureConnect', this );
    }.bind( this );
};
util.inherits( DtlsSocket, EventEmitter );

DtlsSocket.connect = function( port, address, type, callback ) {
    var dgramSocket = dgram.createSocket( type );

    var socket = new DtlsSocket( dgramSocket, { address: address, port: port });
    socket.renegotiate();

    dgramSocket.on( 'message', socket.handle.bind( socket ) );

    if( callback )
        socket.once( 'secureConnect', callback );

    return socket;
};

DtlsSocket.prototype.renegotiate = function() {
    this.handshakeHandler.renegotiate();
};

DtlsSocket.prototype.send = function( buffer, offset, length, callback ) {

    // Slice the buffer if we have offset specified and wrap it into a packet
    // structure that holds the message type as well.
    if( offset )
        buffer = buffer.slice( offset, offset + length );

    var packet = {
        type: dtls.MessageType.applicationData,
        buffer: buffer
    };

    this.recordLayer.send( packet, callback );
};

DtlsSocket.prototype.close = function() {
    if( this.isServer )
        throw new Error(
            'Attempting to close a server socket. Close the server instead' );

    this.dgram.close();
};

DtlsSocket.prototype.handle = function( buffer ) {
    var self = this;

    this.recordLayer.getPackets( buffer, function( packet ) {

        var handler = DtlsSocket.handlers[ packet.type ];

        if( !handler ) {
            var msgType = dtls.MessageTypeName[ packet.type ];
            return log.error( 'Handler not found for', msgType, 'message' );
        }

        handler.call( self, packet );
    });
};

DtlsSocket.handlers = [];
DtlsSocket.handlers[ dtls.MessageType.handshake ] = function( message ) {
    this.handshakeHandler.process( message );
};

DtlsSocket.handlers[ dtls.MessageType.changeCipherSpec ] = function( message ) {
    // Record layer does the work here.
    log.info( 'Changed Cipher Spec' );
};

DtlsSocket.handlers[ dtls.MessageType.applicationData ] = function( message ) {
    this.emit( 'message', message.fragment );
};

module.exports = DtlsSocket;
