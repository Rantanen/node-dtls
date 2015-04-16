
"use strict";

var dtls = require( '../' );
var fs = require( 'fs' );

dtls.setLogLevel( dtls.logLevel.INFO );
var pem = fs.readFileSync( 'server.pem' );

var server = dtls.createServer({
    type: 'udp4',
    key: pem,
    cert: pem
});
server.bind( 4433 );

server.on( 'secureConnection', function( socket ) {

    console.log( 'New connection from ' +
        [ socket.rinfo.address, socket.rinfo.port ].join(':') );

    socket.on( 'message', function( message ) {

        // Get the ascii encoded text content and trim whitespace at the end.
        var inText = message.toString( 'ascii' ).replace( /\s*$/, '' );
        var outText = '[ECHO]' + inText + '[/ECHO]';

        console.log( 'in:  ' + inText );
        console.log( 'out: ' + outText );
        socket.send( new Buffer( outText + '\n', 'ascii' ) );
    });
});

