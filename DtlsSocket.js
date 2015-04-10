
"use strict";

var DtlsSession = require( './DtlsSession' );

var DtlsSocket = function( dgramSocket ) {

    this.sessions = {};

    this.dgram = dgramSocket;
    //this.assembler = new DtlsRecordReader( this.dgram ); 
    //this.assembler.on( 'message', this._onMessage.bind( this ) );
    this.dgram.on( 'message', this._onMessage.bind( this ) );
};

DtlsSocket.prototype.bind = function( port ) {
    this.dgram.bind( port );
};

DtlsSocket.prototype._onMessage = function( message, rinfo ) {

    var sessionKey = rinfo.address + ':' + rinfo.port;
    var session = this.sessions[ sessionKey ];
    if( !session ) {
        this.sessions[ sessionKey ] = session = new DtlsSession( this.dgram, rinfo );
    }

    session.handle( message );
};

module.exports = DtlsSocket;
