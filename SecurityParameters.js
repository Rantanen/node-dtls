
"use strict";

var crypto = require( 'crypto' );
var dtls = require( './dtls' );
var prf = require( './prf' );
var BufferReader = require( './BufferReader' );

var log = require( 'logg' ).getLogger( 'dtls.SecurityParameters' );

var SecurityParameters = function() {

    this.version = null;
    this.entity = dtls.ConnectionEnd.server;

    // Cipher suite prf
    this.prfAlgorithm = dtls.PRFAlgorithm.tlsPrfSha256;

    // Cipher suite cipher
    this.bulkCipherAlgorithm = dtls.BulkCipherAlgorithm.none;
    this.cipherType = dtls.CipherType.block;
    this.encKeyLength = 0;
    this.blockLength = 0;
    this.fixedIvLength = 0;
    this.recordIvLength = 0;

    // Cipher suite mac
    this.macAlgorithm = dtls.MACAlgorithm.none;
    this.macLength = 0;
    this.macKeyLength = 0;

    // Handshake
    this.compressionAlgorithm = dtls.CompressionMethod.none;
    this.masterKey = null;
    this.clientRandom = null;
    this.serverRandom = null;
};

SecurityParameters.prototype.setFrom = function( suite ) {

    this.prfAlgorithm = suite.prf;

    this.bulkCipherAlgorithm = suite.cipher.algorithm;
    this.cipherType = suite.cipher.type;
    this.encKeyLength = suite.cipher.keyMaterial;
    this.blockLength = suite.cipher.blockSize;
    this.fixedIvLength = 0;
    this.recordIvLength = suite.cipher.ivSize;

    this.macAlgorithm = suite.mac.algorithm;
    this.macLength = suite.mac.length;
    this.macKeyLength = suite.mac.keyLength;
};

SecurityParameters.prototype.init = function() {

    var keyBlock = prf( this.version )(
        this.masterKey,
        "key expansion",
        Buffer.concat([ this.serverRandom, this.clientRandom ]),
        this.macKeyLength * 2 + this.encKeyLength * 2 + this.recordIvLength * 2 );

    var bufferReader = new BufferReader( keyBlock );
    this.clientWriteMacKey = bufferReader.readBytes( this.macKeyLength );
    this.serverWriteMacKey = bufferReader.readBytes( this.macKeyLength );
    this.clientWriteKey = bufferReader.readBytes( this.encKeyLength );
    this.serverWriteKey = bufferReader.readBytes( this.encKeyLength );
    this.clientWriteIv = bufferReader.readBytes( this.recordIvLength );
    this.serverWriteIv = bufferReader.readBytes( this.recordIvLength );

    log.info( 'Key content' );
    log.info( 'C-Mac:', this.clientWriteMacKey );
    log.info( 'S-Mac:', this.serverWriteMacKey );
    log.info( 'C-Key:', this.clientWriteKey );
    log.info( 'S-Key:', this.serverWriteKey );
    log.info( 'C-IV: ', this.clientWriteIv );
    log.info( 'S-IV: ', this.serverWriteIv );
};

SecurityParameters.prototype.getDecipher = function( iv ) {
    return crypto.createDecipheriv( 'aes-128-cbc', this.clientWriteKey, iv );
};

SecurityParameters.prototype.getCipher = function( iv ) {
    return crypto.createCipheriv( 'aes-128-cbc', this.serverWriteKey, iv );
};

module.exports = SecurityParameters;
