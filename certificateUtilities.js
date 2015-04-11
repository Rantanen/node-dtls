
"use strict";

var Buffer = require( 'buffer' ).Buffer;
var parseKeys = require( 'parse-asn1' );

var extractCertificate = function( pem ) {

    if( pem instanceof Buffer )
        pem = pem.toString( 'ascii' );

    var beginRe = /^-----BEGIN CERTIFICATE-----$/;
    var endRe = /^-----END CERTIFICATE-----$/;
    var match;

    var certLines = null;
    var lines = pem.split( '\n' );
    for( var l in lines ) {
        var line = lines[l];

        if( !certLines ) {

            // Seek start of a segment
            match = beginRe.exec( line );
            if( !match )
                continue;

            certLines = [];
        } else if( certLines ) {

            match = endRe.exec( line );
            if( match )
                return new Buffer( certLines.join( '' ), 'base64' );

            certLines.push( line );
        }
    }

    return null;
};

module.exports = {
    extractKey: parseKeys,
    extractCertificate: extractCertificate
};
