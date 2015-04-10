
"use strict";

var dtls = require( '../' );

var socket = dtls.createSocket( 'udp4' );
socket.bind( 4433 );
