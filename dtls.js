
"use strict";

var dtls = {

    MessageType: {
        changeCipherSpec: 20,
        alert: 21,
        handshake: 22,
        applicationData: 23
    },

    HandshakeType: {
        helloRequest: 0,
        clientHello: 1,
        serverHello: 2,
        helloVerifyRequest: 3,
        certificate: 11,
        serverKeyExchange: 12,
        certificateRequest: 13,
        serverHelloDone: 14,
        certificateVerify: 15,
        clientKeyExchange: 16,
        finished: 20
    },

    ConnectionEnd: {
        server: 0,
        client: 1
    },

    PRFAlgorithm: {
        tlsPrfSha256: 0
    },

    BulkCipherAlgorithm: {
        none: 0,
        rc4: 1,
        des3: 2,
        aes: 3
    },

    CipherType: {
        stream: 0,
        block: 1,
        aead: 2
    },

    MACAlgorithm: {
        none: 0,
        hmac_md5: 1,
        hmac_sha1: 2,
        hmac_sha256: 3,
        hmac_sha384: 4,
        hmac_sha512: 5
    },

    CompressionMethod: {
        none: 0
    },

    KeyExchange: {
        rsa: 0
    }
};

for( var e in dtls ) {

    var enumeration = dtls[ e ];
    var reversed = [];

    for( var v in enumeration )
        reversed[ enumeration[v] ] = v;

    dtls[ e + 'Name' ] = reversed;
}

module.exports = dtls;
