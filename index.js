
"use strict";

var logg = require( 'logg' );
var DtlsSocket = require( './DtlsSocket' );

var log = logg.getLogger( 'dtls' );
log.setLogLevel( logg.Level.FINE );

module.exports = {
    DtlsSocket: DtlsSocket,

    createSocket: function( options, callback ) {

        var dgram = require( 'dgram' );

        var dgramSocket = dgram.createSocket( options );
        var dtlsSocket = new DtlsSocket( dgramSocket );

        if( callback )
            dtlsSocket.on( 'message', callback );

        return dtlsSocket;
    }
};
