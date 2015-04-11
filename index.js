
"use strict";

var logg = require( 'logg' );
var DtlsSocket = require( './DtlsSocket' );

var log = logg.getLogger( 'dtls' );
log.setLogLevel( logg.Level.FINE );

module.exports = {
    DtlsSocket: DtlsSocket,

    createSocket: DtlsSocket.createSocket,
};
