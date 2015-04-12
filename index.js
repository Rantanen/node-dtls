
"use strict";

var logg = require( 'logg' );
var DtlsSocket = require( './DtlsSocket' );

var log = logg.getLogger( 'dtls' );
log.setLogLevel( logg.Level.FINE );

logg.getLogger( 'dtls.SecurityParameters.digest' ).setLogLevel( logg.Level.WARN );

module.exports = {
    DtlsSocket: DtlsSocket,

    createSocket: DtlsSocket.createSocket,
};
