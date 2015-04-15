
"use strict";

var logg = require( 'logg' );
var DtlsServer = require( './DtlsServer' );
var DtlsSocket = require( './DtlsSocket' );

var log = logg.getLogger( 'dtls' );
log.setLogLevel( logg.Level.FINE );

var logLevels = {};
for( var l in logg.Level )
    logLevels[ l ] = logg.Level[ l ];

logg.getLogger( 'dtls.SecurityParameters.digest' ).setLogLevel( logg.Level.WARN );

module.exports = {
    DtlsServer: DtlsServer,
    createServer: DtlsServer.createServer,
    connect: DtlsSocket.connect,
    setLogLevel: log.setLogLevel.bind( log ),
    logLevel: logLevels
};
