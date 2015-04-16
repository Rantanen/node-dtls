
"use strict";

var dtls = require( '../' );
var fs = require( 'fs' );
var crypto = require( 'crypto' );

dtls.setLogLevel( dtls.logLevel.WARN );

var testIntegrity = true;
var buffer = crypto.pseudoRandomBytes( 1000 );
var stop = false;
var count = 0;
var time = 5000;

var pem = fs.readFileSync( 'server.pem' );

var server = dtls.createServer({
    type: 'udp4',
    key: pem,
    cert: pem
});
server.bind( 23395 );

var serverSocket, clientSocket; 
server.on( 'secureConnection', function( socket ) {
    console.log( 'Server received client#Finished and is ready.' );

    serverSocket = socket;

    serverSocket.on( 'message', function( msg ) {
        if( stop )
            return;
        serverSocket.send( msg );
    });
});


clientSocket = dtls.connect( 23395, 'localhost', 'udp4', function() {
    console.log( 'Client received server#Finished and is ready.' );

    startTest();
});

clientSocket.on( 'message', function( msg ) {
    if( stop )
        return;

    count++;

    if( testIntegrity && !msg.equals( buffer ) ) {
        console.error( 'Buffers differ!' );
        console.error( buffer );
        console.error( msg );
        return;
    }

    clientSocket.send( msg );
});

var startTest = function() {

    count = 0;
    stop = false;

    clientSocket.send( buffer );
    clientSocket.send( buffer );
    clientSocket.send( buffer );
    clientSocket.send( buffer );
    clientSocket.send( buffer );
    clientSocket.send( buffer );
    clientSocket.send( buffer );
    clientSocket.send( buffer );
    clientSocket.send( buffer );

    setTimeout( function() {
        stop = true;
        console.log( 'Packets:    ' + count );
        console.log( 'Size:       ' + buffer.length + ' B' );
        console.log( 'Time:       ' + time + ' ms' );
        console.log( 'Throughput: ' + ( count * buffer.length / ( time/1000 * 1024 ) ) + ' KB/s');
    }, time );
};

