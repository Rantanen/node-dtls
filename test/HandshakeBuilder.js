
"use strict";

var should = require( 'chai' ).should();
var crypto = require( 'crypto' );
var log = require( 'logg' ).getLogger( 'dtls' );
log.setLogLevel( log.SEVERE );

var HandshakeBuilder = require( '../HandshakeBuilder' );
var dtls = require( '../dtls' );

var packets = require( '../packets' );
var DtlsHandshake = require( '../packets/DtlsHandshake' );
var DtlsHelloVerifyRequest = require( '../packets/DtlsHelloVerifyRequest' );
var DtlsProtocolVersion = require( '../packets/DtlsProtocolVersion' );

describe( 'HandshakeBuilder', function() {

    describe( '#add()', function() {

        it( 'should handle unfragmented packets', function() {

            var handshake = createVerifyRequest();

            var builder = new HandshakeBuilder();
            builder.add( handshake );

            builder.merged.should.include.keys( '0' );
            builder.merged[0].msgType.should.equal( handshake.msgType );
            builder.merged[0].body.should.deep.equal( handshake.body );
        });

        it( 'should merge fragmented packets', function() {

            var original = createVerifyRequest();

            var fragment1 = new DtlsHandshake({
                msgType: original.msgType,
                length: original.body.length,
                messageSeq: 0,
                fragmentOffset: 0,
                body: original.body.slice( 0, 10 )
            });

            var fragment2 = new DtlsHandshake({
                msgType: original.msgType,
                length: original.body.length,
                messageSeq: 0,
                fragmentOffset: 10,
                body: original.body.slice( 10 )
            });

            var builder = new HandshakeBuilder();
            builder.add( fragment1 );

            // First fragment written. It should be buffered and not merged.
            builder.buffers.should.include.keys( '0' );
            builder.buffers[0].bytesRead.should.equal( 10 );
            builder.buffers[0].body.slice( 0, 10 ).should.deep.equal( fragment1.body );
            builder.buffers[0].msgType.should.equal( original.msgType );
            builder.merged.should.not.include.keys( '0' );

            builder.add( fragment2 );

            // Second fragment written. Buffer should be empty. Packet should
            // be merged.
            builder.merged.should.include.keys( '0' );
            builder.merged[0].body.should.deep.equal( original.body );
            builder.merged[0].msgType.should.equal( original.msgType );
            builder.buffers.should.not.include.keys( '0' );
        });

        it( 'should handle out of order fragments', function() {

            var original = createVerifyRequest();

            var fragment1 = new DtlsHandshake({
                msgType: original.messageType,
                length: original.body.length,
                messageSeq: 0,
                fragmentOffset: 0,
                body: original.body.slice( 0, 10 )
            });

            var fragment2 = new DtlsHandshake({
                msgType: original.messageType,
                length: original.body.length,
                messageSeq: 0,
                fragmentOffset: 10,
                body: original.body.slice( 10, 20 )
            });

            var fragment3 = new DtlsHandshake({
                msgType: original.messageType,
                length: original.body.length,
                messageSeq: 0,
                fragmentOffset: 20,
                body: original.body.slice( 20 )
            });

            var builder = new HandshakeBuilder();
            builder.add( fragment3 );

            // Third fragment added. It should be queued, not written yet.
            builder.buffers.should.include.keys( '0' );
            builder.buffers[0].bytesRead.should.equal( 0 );
            builder.buffers[0].fragments.length.should.equal( 1 );
            builder.buffers[0].fragments[0].should.deep.equal( fragment3 );
            builder.merged.should.not.include.keys( '0' );

            builder.add( fragment2 );

            // Second fragment added. It should be queued, not written yet.
            builder.buffers.should.include.keys( '0' );
            builder.buffers[0].bytesRead.should.equal( 0 );
            builder.buffers[0].fragments.length.should.equal( 2 );
            builder.buffers[0].fragments[1].should.deep.equal( fragment2 );
            builder.merged.should.not.include.keys( '0' );

            builder.add( fragment1 );

            // First fragment written. Buffer should be empty. Packet should
            // be merged.
            builder.buffers.should.not.include.keys( '0' );
            builder.merged.should.include.keys( '0' );
            builder.merged[0].body.should.deep.equal( original.body );
        });

        it( 'should handle late packets', function() {

            var first = createVerifyRequest();
            var second = createVerifyRequest();

            var builder = new HandshakeBuilder();

            builder.add( first ).should.equal.true;
            builder.add( second ).should.equal.false;
        });

        it( 'should handle late fragments', function() {

            var first = createVerifyRequest();
            var second = createVerifyRequest();

            first.body = first.body.slice( 0, 20 );
            second.body = second.body.slice( 5, 15 );

            var builder = new HandshakeBuilder();

            builder.add( first );
            builder.buffers.should.include.keys( '0' );
            builder.buffers[0].bytesRead.should.equal( 20 );
            builder.buffers[0].body.slice( 0, 20 ).should.deep.equal( first.body );

            builder.add( second );
            builder.buffers.should.include.keys( '0' );
            builder.buffers[0].bytesRead.should.equal( 20 );
            builder.buffers[0].body.slice( 0, 20 ).should.deep.equal( first.body );
        });

        it( 'should handle duplicate early paclets', function() {

            var original = createVerifyRequest();

            var fragment1 = new DtlsHandshake({
                msgType: original.messageType,
                length: original.body.length,
                messageSeq: 0,
                fragmentOffset: 0,
                body: original.body.slice( 0, 10 )
            });

            var fragment2 = new DtlsHandshake({
                msgType: original.messageType,
                length: original.body.length,
                messageSeq: 0,
                fragmentOffset: 10,
                body: original.body.slice( 10, 20 )
            });

            var builder = new HandshakeBuilder();
            builder.add( fragment2 );
            builder.add( fragment2 );

            builder.buffers.should.include.keys( '0' );
            builder.buffers[0].bytesRead.should.equal( 0 );
            builder.buffers[0].fragments.length.should.equal( 2 );

            builder.add( fragment1 );

            builder.buffers[0].bytesRead.should.equal( 20 );
            builder.buffers[0].fragments.length.should.equal( 0 );

            builder.buffers[0].body.slice( 0, 10 ).should.deep.equal(
                fragment1.body );
            builder.buffers[0].body.slice( 10, 20 ).should.deep.equal(
                fragment2.body );
        });
    });

    describe( '#next()', function() {

        it( 'should return false by default', function() {

            var builder = new HandshakeBuilder();

            builder.messageSeqToRead.should.equal( 0 );
            builder.next().should.be.false;
            builder.messageSeqToRead.should.equal( 0 );
        });

        it( 'should return packet when a merged packet exists', function() {

            var original = createVerifyRequest();

            var builder = new HandshakeBuilder();
            builder.add( original );

            var out = builder.next();

            out.should.deep.equal( original );
            builder.messageSeqToRead.should.equal( 1 );
        });

        it( 'should return false when we have incomplete handshake', function() {

            var original = createVerifyRequest();

            var fragment1 = new DtlsHandshake({
                msgType: original.msgType,
                length: original.body.length,
                messageSeq: 0,
                fragmentOffset: 0,
                body: original.body.slice( 0, 10 )
            });

            var fragment2 = new DtlsHandshake({
                msgType: original.msgType,
                length: original.body.length,
                messageSeq: 0,
                fragmentOffset: 10,
                body: original.body.slice( 10 )
            });

            var builder = new HandshakeBuilder();

            builder.next().should.be.false;

            builder.add( fragment1 );

            builder.next().should.be.false;

            builder.add( fragment2 );

            builder.next().should.deep.equal( original );

        });
    });

    describe( '#createHandshakes()', function() {

        it( 'should wrap single handshake', function() {

            var verifyRequest = new packets.HelloVerifyRequest({
                serverVersion: new DtlsProtocolVersion({ major: 1, minor: 2 }),
                cookie: crypto.pseudoRandomBytes( 30 )
            });

            var builder = new HandshakeBuilder();

            var hs = builder.createHandshakes( verifyRequest );

            hs.msgType.should.equal( verifyRequest.messageType );
            hs.length.should.equal( verifyRequest.getBuffer().length );
            hs.messageSeq.should.equal( 0 );
            hs.fragmentOffset.should.equal( 0 );
            hs.body.should.deep.equal( verifyRequest.getBuffer() );
        });

        it( 'should wrap multiple handshakes', function() {

            var helloDone = new packets.ServerHelloDone({});
            var verifyRequest = new packets.HelloVerifyRequest({
                serverVersion: new DtlsProtocolVersion({ major: 1, minor: 2 }),
                cookie: crypto.pseudoRandomBytes( 30 )
            });

            var builder = new HandshakeBuilder();

            var hss = builder.createHandshakes([ helloDone, verifyRequest ]);

            hss[0].msgType.should.equal( helloDone.messageType );
            hss[0].body.should.deep.equal( helloDone.getBuffer() );
            hss[0].messageSeq.should.equal( 0 );

            hss[1].msgType.should.equal( verifyRequest.messageType );
            hss[1].body.should.deep.equal( verifyRequest.getBuffer() );
            hss[1].messageSeq.should.equal( 1 );
        });

    });

    describe( '#fragmentHandshakes()', function() {

        it( 'should fragment single handshake', function() {

            var cert = crypto.pseudoRandomBytes( 1024 );
            var certificate = new packets.Certificate({
                certificateList: [ cert, cert, cert ]
            });

            var builder = new HandshakeBuilder();
            builder.outgoingMessageSeq = 10;
            var hs = builder.createHandshakes( certificate );

            var fragments = builder.fragmentHandshakes( hs );

            fragments.should.have.length( 4 );

            for( var i = 0; i < 4; i++ ) {
                fragments[i].msgType.should.equal( certificate.messageType );
                fragments[i].messageSeq.should.equal( hs.messageSeq );
                fragments[i].length.should.equal( hs.length );
            }

            // Handshake has 12 byte header
            fragments[0].body.should.deep.equal(
                certificate.getBuffer().slice( 0, 1000 ) );
            fragments[1].body.should.deep.equal(
                certificate.getBuffer().slice( 1000, 2000 ) );
            fragments[2].body.should.deep.equal(
                certificate.getBuffer().slice( 2000, 3000 ) );
            fragments[3].body.should.deep.equal(
                certificate.getBuffer().slice( 3000 ) );

            fragments[0].fragmentOffset.should.equal( 0 );
            fragments[1].fragmentOffset.should.equal( 1000 );
            fragments[2].fragmentOffset.should.equal( 2000 );
            fragments[3].fragmentOffset.should.equal( 3000 );
        });

        it( 'should fragment multiple handshakes', function() {

            var cert1 = crypto.pseudoRandomBytes( 1500 );
            var certificate1 = new packets.Certificate({
                certificateList: [ cert1 ]
            });
            var cert2 = crypto.pseudoRandomBytes( 1500 );
            var certificate2 = new packets.Certificate({
                certificateList: [ cert2 ]
            });

            var builder = new HandshakeBuilder();
            builder.outgoingMessageSeq = 10;
            var hs = builder.createHandshakes([ certificate1, certificate2 ]);

            hs.should.have.length( 2 );
            var fragments = builder.fragmentHandshakes( hs );

            fragments.should.have.length( 4 );

            var i;
            for( i = 0; i < 2; i++ ) {
                fragments[i].msgType.should.equal( certificate1.messageType );
                fragments[i].messageSeq.should.equal( hs[0].messageSeq );
                fragments[i].length.should.equal( hs[0].length );
            }
            for( i = 2; i < 4; i++ ) {
                fragments[i].msgType.should.equal( certificate2.messageType );
                fragments[i].messageSeq.should.equal( hs[1].messageSeq );
                fragments[i].length.should.equal( hs[1].length );
            }

            // Handshake has 12 byte header
            fragments[0].body.should.deep.equal(
                certificate1.getBuffer().slice( 0, 1000 ) );
            fragments[1].body.should.deep.equal(
                certificate1.getBuffer().slice( 1000 ) );
            fragments[2].body.should.deep.equal(
                certificate2.getBuffer().slice( 0, 1000 ) );
            fragments[3].body.should.deep.equal(
                certificate2.getBuffer().slice( 1000 ) );

            fragments[0].fragmentOffset.should.equal( 0 );
            fragments[1].fragmentOffset.should.equal( 1000 );
            fragments[2].fragmentOffset.should.equal( 0 );
            fragments[3].fragmentOffset.should.equal( 1000 );
        });

        it( 'should handle buffers', function() {

            var cert = crypto.pseudoRandomBytes( 1024 );
            var certificate = new packets.Certificate({
                certificateList: [ cert ]
            });

            var builder = new HandshakeBuilder();
            builder.outgoingMessageSeq = 10;
            var hs = builder.createHandshakes( certificate );

            var fragments = builder.fragmentHandshakes( hs.getBuffer() );

            fragments.should.have.length( 2 );

            for( var i = 0; i < 2; i++ ) {
                fragments[i].msgType.should.equal( certificate.messageType );
                fragments[i].messageSeq.should.equal( hs.messageSeq );
                fragments[i].length.should.equal( hs.length );
            }

            // Handshake has 12 byte header
            fragments[0].body.should.deep.equal(
                certificate.getBuffer().slice( 0, 1000 ) );
            fragments[1].body.should.deep.equal(
                certificate.getBuffer().slice( 1000 ) );

            fragments[0].fragmentOffset.should.equal( 0 );
            fragments[1].fragmentOffset.should.equal( 1000 );
        });
    });
});

var createVerifyRequest = function() {

    var verifyRequest = new DtlsHelloVerifyRequest({
        serverVersion: new DtlsProtocolVersion({ major: 1, minor: 2 }),
        cookie: crypto.pseudoRandomBytes( 30 )
    });

    var buffer = verifyRequest.getBuffer();

    var handshake = new DtlsHandshake({
        msgType: verifyRequest.messageType,
        length: buffer.length,
        messageSeq: 0,
        fragmentOffset: 0,
        body: buffer
    });

    return handshake;
};
