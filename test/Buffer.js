
"use strict";

var should = require( 'chai' ).should();
var crypto = require( 'crypto' );

var BufferReader = require( '../BufferReader' );
var BufferBuilder = require( '../BufferBuilder' );

var datatypes = {
    Int8: 1, UInt8: 1,
    Int16LE: 2, UInt16LE: 2,
    Int16BE: 2, UInt16BE: 2,
    Int32LE: 4, UInt32LE: 4,
    Int32BE: 4, UInt32BE: 4,
    FloatLE: 4, DoubleLE: 8,
    FloatBE: 4, DoubleBE: 8
};

describe( 'BufferReader', function() {

    Object.keys( datatypes ).forEach( function( dt ) {
        var method = 'read' + dt;
        var size = datatypes[dt];

        describe( '#' + method + '()', function() {

            it( 'should advance offset', function() {
                
                var reader = new BufferReader( new Buffer( size ) );
                reader[ method ]();

                reader.offset.should.equal( size );
            });

            it( 'should read bytes correctly', function() {

                var count = 16;

                var buffer = crypto.pseudoRandomBytes( size * count );
                var reader = new BufferReader( buffer );

                for( var i = 0; i < count; i++ ) {
                    var actual = reader[ method ]();
                    var expected = buffer[ method ]( size * i );

                    if( !isNaN( expected ) )
                        actual.should.equal( expected );
                }
            });

            it( 'should consider optional offset', function() {

                var count = 16;

                var buffer = crypto.pseudoRandomBytes( size * count );
                var reader = new BufferReader( buffer );

                for( var i = 0; i < count; i++ ) {
                    var actual = reader[ method ]( buffer.length - ( size * (i+1) ));
                    var expected = buffer[ method ]( buffer.length - ( size * (i+1) ));

                    if( !isNaN( expected ) )
                        actual.should.equal( expected );
                }
            });
        });
    });

    describe( '#readUInt24BE()', function() {

        it( 'should write bytes correctly', function() {

            var builder = new BufferBuilder();
            var value = Math.floor( Math.random() * 0xffffff );
            builder.writeUInt24BE( value );

            var reader = new BufferReader( builder.getBuffer() );
            var actual = reader.readUInt24BE();

            actual.should.equal( value );
        });
    });

    describe( '#readUInt24LE()', function() {

        it( 'should write bytes correctly', function() {

            var builder = new BufferBuilder();
            var value = Math.floor( Math.random() * 0xffffff );
            builder.writeUInt24LE( value );

            var reader = new BufferReader( builder.getBuffer() );
            var actual = reader.readUInt24LE();

            actual.should.equal( value );
        });
    });

    describe( '#readBytes()', function() {

        it( 'should read bytes correctly', function() {
            var value = crypto.pseudoRandomBytes( 64 );

            var reader = new BufferReader( value );

            for( var i = 0; i < 64; i += 16 ) {

                var actual = reader.readBytes( 16 );
                var expected = value.slice( i, i + 16 );

                actual.should.deep.equal( expected );
            }
        });
    });

    describe( '#seek()', function() {

        it( 'should change position in buffer', function() {

            var buffer = new Buffer( [ 0x10, 0x20, 0x30, 0x40 ] );
            var reader = new BufferReader( buffer );

            reader.readInt8().should.equal( 0x10 );

            reader.seek( 2 );
            reader.readInt8().should.equal( 0x30 );

            reader.seek( 1 );
            reader.readInt8().should.equal( 0x20 );
        });
    });
});

describe( 'BufferBuilder', function() {

    Object.keys( datatypes ).forEach( function( dt ) {
        var method = 'write' + dt;
        var size = datatypes[dt];

        describe( '#' + method + '()', function() {

            it( 'should write bytes correctly', function() {

                var count = 16;

                var builder = new BufferBuilder();
                var buffer = new Buffer( size * count );

                for( var i = 0; i < count; i++ ) {
                    var value = Math.random();

                    builder[method]( value );
                    buffer[method]( value, i * size );
                }

                var actual = builder.getBuffer();
                actual.should.deep.equal( buffer );
            });
        });
    });

    describe( '#writeUInt24BE()', function() {

        it( 'should write bytes correctly', function() {
            var count = 16;
            var size = 3;

            var builder = new BufferBuilder();
            var buffer = new Buffer( 3 * count );

            for( var i = 0; i < count; i++ ) {
                var value = Math.floor( Math.random() * 0xffffff );

                builder.writeUInt24BE( value );
                buffer.writeUInt8( ( value & 0xff0000 ) >> 16, i * size );
                buffer.writeUInt16BE( value & 0xffff, i * size + 1 );
            }

            var actual = builder.getBuffer();
            buffer.should.deep.equal( actual );
        });
    });

    describe( '#writeUInt24LE()', function() {

        it( 'should write bytes correctly', function() {
            var count = 16;
            var size = 3;

            var builder = new BufferBuilder();
            var buffer = new Buffer( size * count );

            for( var i = 0; i < count; i++ ) {
                var value = Math.floor( Math.random() * 0xffffff );

                builder.writeUInt24LE( value );
                buffer.writeUInt8( value & 0xff, i * size );
                buffer.writeUInt16LE( ( value & 0xffff00 ) >> 8, i * size + 1 );
            }

            var actual = builder.getBuffer();
            buffer.should.deep.equal( actual );
        });
    });

    describe( '#writeBytes()', function() {

        it( 'should write bytes correctly', function() {

            var count = 16;
            var size = 8;
            
            var builder = new BufferBuilder();
            var buffer = new Buffer( size * count );

            for( var i = 0; i < count; i++ ) {

                var value = crypto.pseudoRandomBytes( size );
                builder.writeBytes( value );
                value.copy( buffer, i * size );
            }

            var actual = builder.getBuffer();
            buffer.should.deep.equal( actual );
            
        });
    });

});
