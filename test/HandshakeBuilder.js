
"use strict";

var should = require( 'chai' ).should();
var crypto = require( 'crypto' );

var HandshakeBuilder = require( '../HandshakeBuilder' );
var dtls = require( '../dtls' );

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
                body: original.body.slice( 10 )
            });

            var builder = new HandshakeBuilder();
            builder.add( fragment1 );

            // First fragment written. It should be buffered and not merged.
            builder.buffers.should.include.keys( '0' );
            builder.buffers[0].bytesRead.should.equal( 10 );
            builder.buffers[0].body.slice( 0, 10 ).should.deep.equal( fragment1.body );
            builder.merged.should.not.include.keys( '0' );

            builder.add( fragment2 );

            // Second fragment written. Buffer should be empty. Packet should
            // be merged.
            builder.merged.should.include.keys( '0' );
            builder.merged[0].body.should.deep.equal( original.body );
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
