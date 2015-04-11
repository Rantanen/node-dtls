
"use strict";
var crypto = require( 'crypto' );

var hash = function( algo, secret, text ) {

    var sum = crypto.createHmac( algo, secret );
    sum.update( text );
    return sum.digest();
};

var p = function( hashName, secret, seed, length ) {

    var hash_x = hash.bind( null, hashName );

    length = length || 32; 
    var a = function(n) {
        if( n === 0 )
            return seed;

        return hash_x( secret, a( n-1 ) );
    };

    var hashes = [];
    var hashLength = 0;
    for( var i = 1; hashLength < length; i++ ) {

        var hashBytes = hash_x( secret, Buffer.concat([ a(i), seed ]));
        hashLength += hashBytes.length;
        hashes.push( hashBytes );
    }

    return Buffer.concat( hashes, length );
};

var p_md5 = p.bind( null, 'md5' );
var p_sha1 = p.bind( null, 'sha1' );
var p_sha256 = p.bind( null, 'sha256' );

var prf = {};

prf[ ~0 ] = prf[ ~1 ] = function( secret, label, seed, length ) {

    var splitLength = Math.ceil( secret.length / 2 );
    var md5Secret = secret.slice( 0, splitLength );
    var shaSecret = secret.slice( secret.length - splitLength, secret.length );

    var labelSeed = Buffer.concat([ new Buffer( label ), seed ]);

    var md5Bytes = p_md5( md5Secret, labelSeed, length );
    var shaBytes = p_sha1( shaSecret, labelSeed, length );

    for( var i = 0; i < length; i++ )
        md5Bytes[i] = md5Bytes[i] ^ shaBytes[i];

    return md5Bytes;
};

prf[ ~2 ] = function( secret, label, seed, length ) {

    return p_sha256(
        secret,
        Buffer.concat([ new Buffer( label ), seed ]),
        length );
};

module.exports = function( version ) {
    if( version.major !== ~1 )
        throw new Error( 'Unsupported version: ' + 
            [ ~version.major, ~version.minor ].join('.') );

    return prf[ version.minor ];
};
