
"use strict";

var dtls = require( './dtls' );

var CipherSuite = function( id, keyExchange, cipher, mac, prf ) {

    this.id = id;
    this.keyExchange = keyExchange;
    this.cipher = cipher;
    this.mac = mac;


    this.prf = prf || dtls.PRFAlgorithm.tlsPrfSha256;
};

var Cipher = function( algorithm, type, keyMaterial, ivSize, blockSize ) {
    this.algorithm = algorithm;
    this.type = type;
    this.keyMaterial = keyMaterial;
    this.ivSize = ivSize;
    this.blockSize = blockSize;
};

var Mac = function( algorithm, length, keyLength ) {
    this.algorithm = algorithm;
    this.length = length;
    this.keyLength = keyLength;
};

var cipher = {
    none: new Cipher( dtls.BulkCipherAlgorithm.none,
        dtls.CipherType.stream, 0, 0, 0 ),
    rc4_128: new Cipher( dtls.BulkCipherAlgorithm.rc4,
        dtls.CipherType.stream, 16, 0, 0 ),
    des3_ede_cbc: new Cipher( dtls.BulkCipherAlgorithm.des3,
        dtls.CipherType.block, 24, 8, 8 ),
    aes_128_cbc: new Cipher( dtls.BulkCipherAlgorithm.aes,
        dtls.CipherType.block, 16, 16, 16 ),
    aes_256_cbc: new Cipher( dtls.BulkCipherAlgorithm.aes,
        dtls.CipherType.block, 32, 16, 16 )
};

var mac = {
    none: new Mac( dtls.MACAlgorithm.none, 0, 0 ),
    md5: new Mac( dtls.MACAlgorithm.hmac_md5, 16, 16 ),
    sha: new Mac( dtls.MACAlgorithm.hmac_sha1, 20, 20 ),
    sha256: new Mac( dtls.MACAlgorithm.hmac_sha256, 32, 32 ),
};

var suites = {
    TLS_RSA_WITH_AES_128_CBC_SHA: new CipherSuite(
        0x002f, dtls.KeyExchange.rsa, cipher.aes_128_cbc, mac.sha ),
};

for( var s in suites ) {
    suites[s].name = s;
}

module.exports = suites;

