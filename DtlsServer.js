
"use strict";

var util = require( 'util' );
var EventEmitter = require( 'events' ).EventEmitter;
var DtlsSocket = require( './DtlsSocket' );
var KeyContext = require( './KeyContext' );

var DtlsServer = function( dgramSocket, options ) {

    this.dgram = dgramSocket;
    this.keyContext = new KeyContext( options );

    this.sockets = {};

    this.dgram.on( 'message', this._onMessage.bind( this ) );
};
util.inherits( DtlsServer, EventEmitter );

DtlsServer.createServer = function( options, callback ) {

    var dgram = require( 'dgram' );

    var dgramSocket = dgram.createSocket( options );
    var dtlsServer = new DtlsServer( dgramSocket, options );

    if( callback )
        dtlsServer.on( 'message', callback );

    return dtlsServer;
};

DtlsServer.prototype.bind = function( port ) {
    if( !this.keyContext )
        throw new Error(
            'Cannot act as a server without a certificate. ' +
            'Use options.cert to specify certificate.' );

    this.dgram.bind( port );
};

DtlsServer.prototype._onMessage = function( message, rinfo ) {

    var socketKey = rinfo.address + ':' + rinfo.port;
    var socket = this.sockets[ socketKey ];
    if( !socket ) {
        this.sockets[ socketKey ] = socket =
            new DtlsSocket( this.dgram, rinfo, this.keyContext );

        socket.once( 'secureConnect', function( socket ) {
            this.emit( 'secureConnection', socket );
        }.bind( this ));
    }

    socket.handle( message );
};

module.exports = DtlsServer;
