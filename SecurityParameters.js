
"use strict";

var dtls = require( './dtls' );

var SecurityParameters = function() {

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

module.exports = SecurityParameters;
