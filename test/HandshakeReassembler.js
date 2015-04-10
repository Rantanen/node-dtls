/*global describe:true, it:true */

"use strict";

var should = require( 'chai' ).should();
var crypto = require( 'crypto' );

var DtlsHandshake = require( '../packets/DtlsHandshake' );
var HandshakeReassembler = require( '../HandshakeReassembler' );

describe( 'HandshakeReassembler', function() {

    describe( '#ctor()', function() {

        it( 'should copy handshake properties', function() {

            var handshake = new DtlsHandshake();
            handshake.msgType = 123;
            handshake.length = 234;
            handshake.messageSeq = 345;

            var reassembler = new HandshakeReassembler( handshake );

            reassembler.msgType.should.equal( handshake.msgType );
            reassembler.length.should.equal( handshake.length );
            reassembler.messageSeq.should.equal( handshake.messageSeq );
            reassembler.body.length.should.equal( handshake.length );
        });
    });

    describe( '#merge()', function() {

        it( 'should buffer early messages', function() {

            var handshake = new DtlsHandshake();
            handshake.fragmentOffset = 10;
            handshake.length = 20;
            handshake.body = new Buffer(10);

            var reassembler = new HandshakeReassembler( handshake );
            reassembler.merge( handshake );

            reassembler.offset.should.equal( 0 );
            reassembler.buffered.length.should.equal( 1 );
        });

        it( 'should merge current messages', function() {

            var handshake = new DtlsHandshake();
            handshake.msgType = 1;
            handshake.length = 100;
            handshake.fragmentOffset = 0;
            handshake.body = new Buffer([
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0 ]);

            var reassembler = new HandshakeReassembler( handshake );
            reassembler.merge( handshake );

            reassembler.offset.should.equal( 10 );
            reassembler.buffered.length.should.equal( 0 );
            reassembler.body.slice( 0, 10 ).should.deep.equal( handshake.body );
        });

        it( 'should replay buffer when early packets arrive', function() {

            var handshake1 = new DtlsHandshake();
            handshake1.msgType = 1;
            handshake1.length = 100;
            handshake1.fragmentOffset = 10;
            handshake1.body = crypto.pseudoRandomBytes( 10 );

            var handshake2 = new DtlsHandshake();
            handshake2.msgType = 1;
            handshake2.length = 100;
            handshake2.fragmentOffset = 0;
            handshake2.body = crypto.pseudoRandomBytes( 10 );

            var reassembler = new HandshakeReassembler( handshake1 );
            reassembler.merge( handshake1 );

            reassembler.buffered.length.should.equal( 1 );

            reassembler.merge( handshake2 );

            reassembler.buffered.length.should.equal( 0 );
            reassembler.offset.should.equal( 20 );
            reassembler.body.slice( 0, 10 ).should.deep.equal( handshake2.body );
            reassembler.body.slice( 10, 20 ).should.deep.equal( handshake1.body );
        });

        it( 'should handle overlapping packets', function() {

            var handshake1 = new DtlsHandshake();
            handshake1.msgType = 1;
            handshake1.length = 100;
            handshake1.fragmentOffset = 2;
            handshake1.body = new Buffer([ 0x30, 0x40, 0x50, 0x60, 0x70 ]);

            var handshake2 = new DtlsHandshake();
            handshake2.msgType = 1;
            handshake2.length = 100;
            handshake2.fragmentOffset = 0;
            handshake2.body = new Buffer([ 0x10, 0x20, 0x30, 0x40 ]);

            var reassembler = new HandshakeReassembler( handshake1 );
            reassembler.merge( handshake1 );

            reassembler.buffered.length.should.equal( 1 );

            reassembler.merge( handshake2 );

            reassembler.buffered.length.should.equal( 0 );
            reassembler.offset.should.equal( 7 );
            reassembler.body.slice( 0, 4 ).should.deep.equal( handshake2.body );
            reassembler.body.slice( 2, 7 ).should.deep.equal( handshake1.body );
        });

        it( 'should return DtlsHandshake when handshake is whole', function() {

            var fragments = [];
            for( var i = 0; i < 10; i += 2 ) {
                var fragment = new DtlsHandshake();
                fragment.msgType = 2;
                fragment.length = 10;
                fragment.fragmentOffset = i;
                fragment.body = crypto.pseudoRandomBytes( 2 );
                fragments.push( fragment );
            }

            var reassembler = new HandshakeReassembler( fragments[0] );

            reassembler.merge( fragments[0] ).should.be.false;
            reassembler.merge( fragments[1] ).should.be.false;
            reassembler.merge( fragments[2] ).should.be.false;
            reassembler.merge( fragments[3] ).should.be.false;
            reassembler.merge( fragments[4] ).should.be.DtlsHandshake;

        });

        it( 'should handle multiple early packets', function() {

            var hs1 = new DtlsHandshake();
            hs1.msgType = 1;
            hs1.length = 10;
            hs1.fragmentOffset = 6;
            hs1.body = new Buffer([ 0x06, 0x07 ]);

            var hs2 = new DtlsHandshake();
            hs2.msgType = 1;
            hs2.length = 10;
            hs2.fragmentOffset = 2;
            hs2.body = new Buffer([ 0x02, 0x03, 0x04, 0x05 ]);

            var hs3 = new DtlsHandshake();
            hs3.msgType = 1;
            hs3.length = 10;
            hs3.fragmentOffset = 0;
            hs3.body = new Buffer([ 0x00, 0x01 ]);

            var reassembler = new HandshakeReassembler( hs1 );

            reassembler.merge( hs1 );
            reassembler.merge( hs2 );

            reassembler.buffered.length.should.equal( 2 );
            reassembler.offset.should.equal( 0 );

            reassembler.merge( hs3 );

            reassembler.offset.should.equal( 8 );
            reassembler.buffered.length.should.equal( 0 );
            reassembler.body.slice( 0, 2 ).should.deep.equal( hs3.body );
            reassembler.body.slice( 2, 6 ).should.deep.equal( hs2.body );
            reassembler.body.slice( 6, 8 ).should.deep.equal( hs1.body );
        });

        it( 'should ignore retransmitted packets', function() {

            var hs = new DtlsHandshake();
            hs.msgType = 1;
            hs.length = 10;
            hs.fragmentOffset = 0;
            hs.body = new Buffer([ 0x01, 0x02, 0x03, 0x04, 0x05 ]);

            var reassembler = new HandshakeReassembler( hs );
            
            reassembler.merge( hs );

            reassembler.offset.should.equal( 5 );
            reassembler.body.slice( 0, 5 ).should.deep.equal( hs.body );

            reassembler.merge( hs );
            
            reassembler.offset.should.equal( 5 );
            reassembler.body.slice( 0, 5 ).should.deep.equal( hs.body );
        });
    });
});
