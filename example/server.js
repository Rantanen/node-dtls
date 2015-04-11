
"use strict";

var dtls = require( '../' );
var fs = require( 'fs' );

var pem = fs.readFileSync( 'server.pem' );

var socket = dtls.createSocket({
    type: 'udp4',
    key: pem,
    cert: pem
});
socket.bind( 4433 );
