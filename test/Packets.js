
"use strict";

var should = require( 'chai' ).should();

var DtlsHandshake = require( '../packets/DtlsHandshake' );

describe( 'DtlsHandshake', function() {

    it( 'should be readable', function() {

        var buffer = new Buffer([
            0x01,
            0x02, 0x03, 0x04,
            0x05, 0x06,
            0x07, 0x08, 0x09,
            0x00, 0x00, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14
        ]);

        var dtlsHandshake = new DtlsHandshake( buffer );

        dtlsHandshake.msgType.should.equal( 0x01 );
        dtlsHandshake.length.should.equal( 0x020304 );
        dtlsHandshake.messageSeq.should.equal( 0x0506 );
        dtlsHandshake.fragmentOffset.should.equal( 0x070809 );
        dtlsHandshake.body.should.deep.equal( new Buffer([ 0x10, 0x11, 0x12, 0x13, 0x14 ]) );
    });
});
