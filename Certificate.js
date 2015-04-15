
"use strict";

var asn = require( 'asn1.js' );
var fs = require( 'fs' );

var X509Certificate = asn.define( 'X509Certificate', function() {
    this.seq().obj(
        this.key( 'tbsCertificate' ).use( TBSCertificate ),
        this.key( 'signatureAlgorithm' ).use( AlgorithmIdentifier ),
        this.key( 'signatureValue' ).bitstr()
    );
});

var TBSCertificate = asn.define( 'TBSCertificate', function() {
    this.seq().obj(
        this.key( 'version' ).explicit(0).int(),
        this.key( 'serialNumber' ).int(),
        this.key( 'signature' ).use( AlgorithmIdentifier ),
        this.key( 'issuer' ).use( Name ),
        this.key( 'validity' ).use( Validity ),
        this.key( 'subject' ).use( Name ),
        this.key( 'subjectPublicKeyInfo' ).use( SubjectPublicKeyInfo ),
        this.key( 'issuerUniqueID' ).implicit(1).bitstr().optional(),
        this.key( 'subjectUniqueID' ).implicit(2).bitstr().optional(),
        this.key( 'extensions' ).explicit(3).seqof( Extension ).optional()
    );
});

var AlgorithmIdentifier = asn.define( 'AlgorithmIdentifier', function() {
    this.seq().obj(
        this.key( 'algorithm' ).objid(),
        this.key( 'parameters' ).optional()
    );
});

var Name = asn.define( 'Name', function() {
    this.choice({
        rdnSequence: this.use( RDNSequence )
    });
});

var RDNSequence = asn.define( 'RDNSequence', function() {
    this.seqof( RelativeDistinguishedName );
});

var RelativeDistinguishedName = asn.define( 'RelativeDistinguishedName', function() {
    this.setof( AttributeTypeValue );
});

var AttributeTypeValue = asn.define( 'AttributeTypeValue', function() {
    this.seq().obj(
        this.key( 'type' ).objid(),
        this.key( 'value' ).any()
    );
});

var Validity = asn.define( 'Validity', function() {
    this.seq().obj(
        this.key( 'notBefore' ).use( Time ),
        this.key( 'notAfter' ).use( Time )
    );
});

var Time = asn.define( 'Time', function() {
    this.choice({
        utcTime: this.utctime(),
        generalTime: this.gentime()
    });
});

var SubjectPublicKeyInfo = asn.define( 'SubjectPublicKeyInfo', function() {
    this.seq().obj(
        this.key( 'algorithm' ).use( AlgorithmIdentifier ),
        this.key( 'subjectPublicKey' ).bitstr()
    );
});

var Extension = asn.define( 'Extension', function() {
    this.seq().obj(
        this.key( 'extnID' ).objid(),
        this.key( 'critical' ).bool().def( false ),
        this.key( 'extnValue' ).octstr()
    );
});

var RSAPublicKey = asn.define( 'RSAPublicKey', function() {
    this.seq().obj(
        this.key( 'modulus' ).int(),
        this.key( 'publicExponent' ).int()
    );
});

exports.parse = function( data ) {
    return X509Certificate.decode( data, 'der' );
};

exports.getPublicKey = function( data ) {
    if( data.tbsCertificate )
        data = data.tbsCertificate;

    if( !data.subjectPublicKeyInfo )
        data = X509Certificate.decode( data, 'der' ).tbsCertificate;

    console.log( '------------------------------------------' );
    console.log( data );
    console.log( '------------------------------------------' );
    console.log( data.subjectPublicKeyInfo.subjectPublicKey.data );
    console.log( '------------------------------------------' );
    var key = RSAPublicKey.decode( data.subjectPublicKeyInfo.subjectPublicKey.data, 'der' );
    return key;
};

exports.getPublicKeyPem = function( data ) {
    if( data.tbsCertificate )
        data = data.tbsCertificate;

    if( !data.subjectPublicKeyInfo )
        data = X509Certificate.decode( data, 'der' ).tbsCertificate;

    var key = SubjectPublicKeyInfo.encode(
        data.subjectPublicKeyInfo, 'der' )
            .toString( 'base64' );

    var pem = '-----BEGIN PUBLIC KEY-----\n';
    while( key.length > 64 ) {
        pem += key.substr( 0, 64 ) + '\n';
        key = key.substr( 64 );
    }
    pem += key + '\n-----END PUBLIC KEY-----';
    return pem;
};

exports.print = function( cert ) {

    if( cert.tbsCertificate )
        cert = cert.tbsCertificate;
    else
        cert = exports.parse( cert ).tbsCertificate;

    console.log( 'Certificate:' );
    console.log( '    Data:' );
    console.log( '        Version: %d (0x%d)',
        cert.version + 1,
        cert.version.toString( 16 ) );
    console.log( '        Serial Number: %d (0x%d)',
        cert.serialNumber.toString(),
        cert.serialNumber.toString( 16 ) );

    // There should prolly be one more level of indent below.
    // The current indent matches openssl -text flag.
    console.log( '    Signature Algorithm: %s', getAlgorithm( cert.signature.algorithm ) );
    console.log( '        Issuer: ...' );
    console.log( '        Validity' );
    console.log( '            Not Before: %s', new Date( cert.validity.notBefore.value ) ) ;
    console.log( '            Not After: %s', new Date( cert.validity.notAfter.value ) ) ;
    console.log( '    Subject: ...' );
    console.log( '    Subject Public Key Info:' );
    console.log( '        PublicKeyAlgorithm: %s', getAlgorithm( cert.subjectPublicKeyInfo.algorithm.algorithm ) );

    var publicKey = RSAPublicKey.decode( cert.subjectPublicKeyInfo.subjectPublicKey.data, 'der' );

    console.log( publicKey );
};

var getIssuer = function( issuer ) {
    // TODO: Couldn't find the attribute types. Plus the names contain more
    // silly ASN.1 encoding which I can't be bothered looking at now. ":D"
    //
    // RFC 3280 seemst to have something around page 93.
    return '(encoded)';
};

var algorithms = {
    '1.2.840.113549.2.1': 'md2',
    '1.2.840.113549.1.1.2': 'md2rsa',
    '1.2.840.113549.2.5': 'md5',
    '1.2.840.113549.1.1.4': 'md5rsa',
    '1.3.14.3.2.26': 'sha1',
    '1.2.840.10040.4.3': 'sha1dsa',
    '1.2.840.10045.4.1': 'sha1ecdsa',
    '1.2.840.113549.1.1.5': 'sha1rsa',
    '2.16.840.1.101.3.4.2.4': 'sha224',
    '1.2.840.113549.1.1.14': 'sha224rsa',
    '2.16.840.1.101.3.4.2.1': 'sha256',
    '1.2.840.113549.1.1.11': 'sha256rsa',
    '2.16.840.1.101.3.4.2.2': 'sha384',
    '1.2.840.113549.1.1.12': 'sha384rsa',
    '2.16.840.1.101.3.4.2.3': 'sha512',
    '1.2.840.113549.1.1.13': 'sha512rsa'
};

var getAlgorithm = function( a ) {
    return algorithms[ a.join('.') ] || a.join('.');
};
