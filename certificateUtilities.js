
"use strict";

var Buffer = require( 'buffer' ).Buffer;

var extractKeys = function( pem ) {

    if( pem instanceof Buffer )
        pem = pem.toString( 'ascii' );

    var lines = pem.split( '\n' );

    var beginRe = /^-----BEGIN ([A-Z ]+)-----$/;
    var endRe = /^-----END ([A-Z ]+)-----$/;
    var match;

    var value = {};
    var current = null;
    for( var l in lines ) {
        var line = lines[l];

        if( !current ) {

            // Seek start of a segment
            match = beginRe.exec( line );
            if( !match )
                continue;

            current = {
                type: ( match[1] === 'PRIVATE KEY' ) ? 'key' : 'certificate',
                value: []
            };
        } else if( current ) {

            match = endRe.exec( line );
            if( match ) {
                value[ current.type ] = new Buffer( current.value.join( '' ), 'base64' );
                current = null;
                continue;
            }

            current.value.push( line );
        }
    }

    return value;
};

module.exports = {
    extractKeys: extractKeys
};
