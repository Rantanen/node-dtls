
"use strict";

var should = require( 'chai' ).should();
var crypto = require( 'crypto' );
var packets = require( '../packets' );

var SecurityParameterContainer = require( '../SecurityParameterContainer' );

describe( 'SecurityParameterContainer', function() {

    describe( '#ctor()', function() {
        it( 'should init correctly', function() {

            var spc = new SecurityParameterContainer();

            should.not.exist( spc.pending );
            spc.current.should.equal( 0 );
            should.exist( spc.parameters[ 0 ] );
            spc.parameters[0].should.equal( spc.first );
        });
    });

    describe( '#initNew()', function() {

        it( 'should create new pending parameter', function() {

            var spc = new SecurityParameterContainer();

            should.not.exist( spc.pending );

            var version = new packets.ProtocolVersion( ~1, ~2 );
            var pending = spc.initNew( version );

            should.exist( spc.pending );
            pending.should.equal( spc.pending );
            pending.version.should.equal( version );

            spc.current.should.equal( 0 );
            should.exist( spc.parameters[ spc.pending.epoch ] );
        });
    });

    describe( '#getcurrent()', function() {

        it( 'should get the parameters for first epoch', function() {

            var spc = new SecurityParameterContainer();

            var current = spc.getCurrent( 0 );

            current.should.equal( spc.first );
        });

        it( 'should get the parameters for random epoch', function() {

            var spc = new SecurityParameterContainer();

            var obj = { params: 1 };
            spc.parameters[ 123 ] = obj;

            var current = spc.getCurrent( 123 );

            current.should.equal( obj );
        });
    });

    describe( '#get()', function() {

        it( 'should get the parameters for first packet', function() {

            var spc = new SecurityParameterContainer();

            var current = spc.get({ epoch: 0 });

            current.should.equal( spc.first );
        });

        it( 'should get the parameters for random packet', function() {

            var spc = new SecurityParameterContainer();

            var obj = { params: 1 };
            spc.parameters[ 123 ] = obj;

            var current = spc.get({ epoch: 123 });

            current.should.equal( obj );
        });
    });

    describe( '#changeCipher()', function() {

        it( 'should change the current parameters', function() {

            var spc = new SecurityParameterContainer();
            var version = new packets.ProtocolVersion( ~1, ~2 );
            var pending = spc.initNew( version );

            pending.clientRandom = new Buffer( 10 );
            pending.serverRandom = new Buffer( 10 );
            pending.masterKey = new Buffer( 10 );

            pending.should.not.equal( spc.first );
            spc.parameters[ spc.current ].should.equal( spc.first );

            spc.changeCipher( 0 );

            spc.parameters[ spc.current ].should.equal( spc.pending );
            spc.parameters[ spc.current ].should.not.equal( spc.first );
        });

        it( 'should refuse to skip epochs', function() {

            var spc = new SecurityParameterContainer();
            spc.initNew( new packets.ProtocolVersion( ~1, ~2 ) );

            (function() {
                spc.changeCipher( 10 );
            }).should.not.throw( Error );

            spc.current.should.equal( 0 );
        });
    });
});
