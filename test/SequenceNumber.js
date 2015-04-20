
"use strict";

var should = require( 'chai' ).should();
var crypto = require( 'crypto' );

var SequenceNumber = require( '../SequenceNumber' );

describe( 'SequenceNumber', function() {
    
    describe( '#ctor()', function() {
        it( 'should init correctly', function() {

            var sn = new SequenceNumber();

            sn.current.should.deep.equal( new Buffer([ 0, 0, 0, 0, 0, 0 ]) );
        });
    });

    describe( '#next()', function() {
        it( 'should increase counter correctly', function() {

            var sn = new SequenceNumber();

            sn.current.should.deep.equal( new Buffer([ 0, 0, 0, 0, 0, 0 ]) );

            var next = sn.next();
            
            next.should.deep.equal( new Buffer([ 0, 0, 0, 0, 0, 1 ]) );
            sn.current.should.deep.equal( next );
        });

        it( 'should overflow correctly', function() {

            var sn = new SequenceNumber();
            sn.current = new Buffer([ 0, 0, 0, 0, 0, 0xff ]);

            var next = sn.next();

            next.should.deep.equal( new Buffer([ 0, 0, 0, 0, 1, 0 ]) );
            sn.current.should.deep.equal( next );
        });

        it( 'should cascade the overflow', function() {

            var sn = new SequenceNumber();
            sn.current = new Buffer([ 0, 0xff, 0xff, 0xff, 0xff, 0xff ]);

            var next = sn.next();

            next.should.deep.equal( new Buffer([ 1, 0, 0, 0, 0, 0 ]) );
            sn.current.should.deep.equal( next );
        });

        it( 'should overflow back to zero', function() {

            var sn = new SequenceNumber();
            sn.current = new Buffer([ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ]);

            var next = sn.next();

            next.should.deep.equal( new Buffer([ 0, 0, 0, 0, 0, 0 ]) );
            sn.current.should.deep.equal( next );
        });
    });
});
