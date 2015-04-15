
"use strict";

var dtls = require( '../' );
var fs = require( 'fs' );

dtls.setLogLevel( dtls.logLevel.FINE );
var pem = fs.readFileSync( 'server.pem' );

var client = dtls.connect( 4433, 'localhost', 'udp4', function() {
    client.send( new Buffer( 'foo\n' ) );
});

client.on( 'message', function( msg ) {
    console.log( msg );
});
