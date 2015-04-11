
"use strict";

var certificateUtilities = require( './certificateUtilities' );

var KeyContext = function( options ) {

    this.key = options.key;

    if( options.key )
        this.privateKey = certificateUtilities.extractKey( options.key );

    if( options.cert )
        this.certificate = certificateUtilities.extractCertificate( options.cert );
};

module.exports = KeyContext;
