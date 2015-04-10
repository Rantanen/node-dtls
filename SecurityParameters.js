
"use strict";

var dtls = require( './dtls' );

var SecurityParameters = function() {

    this.entity = dtls.ConnectionEnd.server;
    this.prfAlgorithm = dtls.PRFAlgorithm.tlsPrfSha256;
    this.bulkCipherAlgorithm = dtls.BulkCipherAlgorithm.none;
    this.cipherType = dtls.CipherType.block;
    this.encKeyLength = 0;
    this.blockLength = 0;
    this.fixedIvLength = 0;
    this.recordIvLength = 0;
    this.macAlgorithm = dtls.MACAlgorithm.none;
    this.macLength = 0;
    this.macKeyLength = 0;
    this.compressionAlgorithm = dtls.CompressionMethod.none;
    this.masterKey = null;
    this.clientRandom = null;
    this.serverRandom = null;
};

module.exports = SecurityParameters;
