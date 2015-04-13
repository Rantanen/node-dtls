
"use strict";

var logg = require( 'logg' );
var DtlsServer = require( './DtlsServer' );

var log = logg.getLogger( 'dtls' );
log.setLogLevel( logg.Level.FINE );

var logLevels = {};
for( var l in logg.Level )
    logLevels[ l ] = logg.Level[ l ];

logg.getLogger( 'dtls.SecurityParameters.digest' ).setLogLevel( logg.Level.WARN );

module.exports = {
    DtlsServer: DtlsServer,
    createServer: DtlsServer.createServer,
    setLogLevel: log.setLogLevel.bind( log ),
    logLevel: logLevels
};
