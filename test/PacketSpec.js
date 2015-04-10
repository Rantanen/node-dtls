
"use strict";

var should = require( 'chai' ).should();
var crypto = require( 'crypto' );

var Packet = require( '../packets/Packet' );
var PacketSpec = require( '../packets/PacketSpec' );


describe( 'PacketSpec', function() {

    var unsignedSpec = new PacketSpec([
        { name: 'uint8_1', type: 'uint8' },
        { name: 'uint8_2', type: 'uint8' },
        { name: 'uint16_1', type: 'uint16' },
        { name: 'uint16_2', type: 'uint16' },
        { name: 'uint24_1', type: 'uint24' },
        { name: 'uint24_2', type: 'uint24' },
        { name: 'uint32_1', type: 'uint32' },
        { name: 'uint32_2', type: 'uint32' },
    ]);

    var signedSpec = new PacketSpec([
        { name: 'int8_1', type: 'int8' },
        { name: 'int8_2', type: 'int8' },
        { name: 'int16_1', type: 'int16' },
        { name: 'int16_2', type: 'int16' },
        { name: 'int32_1', type: 'int32' },
        { name: 'int32_2', type: 'int32' },
    ]);

    var variableSpec = new PacketSpec([
        { name: 'var8', type: 'var8' },
        { name: 'var16', type: 'var16' },
        { name: 'var24', type: 'var24' },
        { name: 'var32', type: 'var32' }
    ]);

    var bytesSpec = new PacketSpec([
        { name: 'bytes1', type: 'bytes', size: 8 },
        { name: 'bytes2', type: 'bytes', size: 8 }
    ]);

    var Version = function( data ) { Packet.call( this, data ); };
    Version.prototype = Object.create( Packet );
    Version.prototype.spec = new PacketSpec([
        { major: 'uint8' },
        { minor: 'uint8' }
    ]);

    var VersionRange = function( data ) { Packet.call( this, data ); };
    VersionRange.prototype = Object.create( Packet );
    VersionRange.prototype.spec = new PacketSpec([
        { min: Version },
        { max: Version }
    ]);

    var advancedVariableSpec = new PacketSpec([
        { name: 'var8uint16', type: 'var8', itemType: 'uint16' },
        { name: 'var8version', type: 'var8', itemType: Version },
        { name: 'var8var8Version', type: 'var8', itemType: { type: 'var8', itemType: Version } }
    ]);

    var customSpec = new PacketSpec([
        {
            name: 'custom',
            read: function( reader ) {
                var arr = [];
                var value = reader.readUInt8();
                while( value !== 0 ) {
                    arr.push( value );
                    value = reader.readUInt8();
                }
                return arr;
            },
            write: function( builder, value ) {
                for( var i = 0; i < value.length; i++ ) {
                    builder.writeUInt8( value[i] );
                }
                builder.writeUInt8( 0 );
            }
        }]);

    describe( '#ctor()', function() {
        it( 'should handle normal specs', function() {

            var stdSpec = new PacketSpec([
                { name: 'works', type: 'uint8' }
            ]);

            stdSpec.spec.length.should.equal( 1 );
            stdSpec.spec[0].name.should.equal( 'works' );
            stdSpec.spec[0].type.should.equal( 'uint8' );
        });

        it( 'should handle shorthand specs', function() {

            var stdSpec = new PacketSpec([
                { works: 'uint8' }
            ]);

            stdSpec.spec.length.should.equal( 1 );
            stdSpec.spec[0].name.should.equal( 'works' );
            stdSpec.spec[0].type.should.equal( 'uint8' );
        });

        it( 'should handle nested specs', function() {

            var VersionRange = function() {};
            var spec = new PacketSpec([
                { max: Version },
                { min: Version }
            ]);
        });

        it( 'should validate specs', function() {

            (function() {
                new PacketSpec([{ fail: 'badType' }]);
            }).should.throw( Error );

            (function() {
                new PacketSpec([{ name: 'fail', read: function() {} }]);
            }).should.throw( Error );

            (function() {
                new PacketSpec([{ name: 'fail', write: function() {} }]);
            }).should.throw( Error );
        });
    });

    describe( '#read()', function() {
        
        it( 'should read unsigned numbers correctly', function() {

            var buffer = new Buffer([
                0x0f,
                0xf0,
                0x0f, 0x0f,
                0xf0, 0xf0,
                0x11, 0x22, 0x33,
                0xff, 0xee, 0xdd,
                0x11, 0x22, 0x33, 0x44,
                0xff, 0x77, 0x66, 0x55,
            ]);

            var obj = {};
            unsignedSpec.read( buffer, obj );

            obj.uint8_1.should.equal( 0x0f );
            obj.uint8_2.should.equal( 0xf0 );
            obj.uint16_1.should.equal( 0x0f0f );
            obj.uint16_2.should.equal( 0xf0f0 );
            obj.uint24_1.should.equal( 0x112233 );
            obj.uint24_2.should.equal( 0xffeedd );
            obj.uint32_1.should.equal( 0x11223344 );
            obj.uint32_2.should.equal( 0xff776655 );
        });

        it( 'should read signed numbers correctly', function() {
            var buffer = new Buffer([
                0x01,
                0xff,
                0x10, 0x01,
                0xff, 0xff,
                0x10, 0x00, 0x00, 0x01,
                0xff, 0xff, 0xff, 0xff
            ]);

            var obj = {};
            signedSpec.read( buffer, obj );

            obj.int8_1.should.equal( 0x01 );
            obj.int8_2.should.equal( -1 );
            obj.int16_1.should.equal( 0x1001 );
            obj.int16_2.should.equal( -1 );
            obj.int32_1.should.equal( 0x10000001 );
            obj.int32_2.should.equal( -1 );
        });

        it( 'should read variable length fields', function() {

            var buffer = new Buffer([
                0x03, 0x00, 0x01, 0x02,
                0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04,
                0x00, 0x00, 0x02, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03
            ]);

            var obj = {};
            variableSpec.read( buffer, obj );

            obj.var8.should.deep.equal( new Buffer([ 0x00, 0x01, 0x02 ]) );
            obj.var16.should.deep.equal( new Buffer([ 0x00, 0x01, 0x02, 0x03, 0x04 ]) );
            obj.var24.should.deep.equal( new Buffer([ 0x00, 0x01 ]) );
            obj.var32.should.deep.equal( new Buffer([ 0x00, 0x01, 0x02, 0x03 ]) );
        });

        it( 'should read byte array', function() {

            var bytes1 = new Buffer([ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 ]);
            var bytes2 = new Buffer([ 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00 ]);

            var buffer = Buffer.concat([ bytes1, bytes2 ]);
            var obj = {};
            bytesSpec.read( buffer, obj );

            obj.bytes1.should.deep.equal( bytes1 );
            obj.bytes2.should.deep.equal( bytes2 );
        });

        it( 'should read custom data', function() {

            var buffer = new Buffer([ 0x01, 0x03, 0x05, 0x00 ]);

            var obj = {};
            customSpec.read( buffer, obj );

            obj.custom.should.deep.equal([ 0x01, 0x03, 0x05 ]);
        });

        it( 'should read nested data', function() {

            var buffer = new Buffer([ 0x01, 0x02, 0x03, 0x04 ]);

            var obj = new VersionRange();
            obj.spec.read( buffer, obj );

            obj.min.major.should.equal( 0x01 );
            obj.min.minor.should.equal( 0x02 );
            obj.max.major.should.equal( 0x03 );
            obj.max.minor.should.equal( 0x04 );
        });

        it( 'should read advanced variable length item lists', function() {

            var buffer = new Buffer([
                0x06, 0x01, 0x02, 0xff, 0x00, 0x00, 0xff,
                0x06, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
                0x08, 0x04, 0x10, 0x20, 0x30, 0x40, 0x02, 0x10, 0x20
            ]);

            var obj = {};
            advancedVariableSpec.read( buffer, obj );

            obj.var8uint16.should.deep.equal( [ 0x0102, 0xff00, 0xff ] );
            obj.var8version.should.deep.equal( [
                new Version({ major: 0x10, minor: 0x20 }),
                new Version({ major: 0x30, minor: 0x40 }),
                new Version({ major: 0x50, minor: 0x60 })
            ]);
            obj.var8var8Version.should.deep.equal( [
                [ 
                    new Version({ major: 0x10, minor: 0x20 }),
                    new Version({ major: 0x30, minor: 0x40 })
                ], [
                    new Version({ major: 0x10, minor: 0x20 })
                ]
            ]);

        });
    });

    describe( '#write()', function() {

        it( 'should write unsigned numbers correctly', function() {
            
            var obj = {
                uint8_1: 0x10,
                uint8_2: 0xf0,
                uint16_1: 0x0110,
                uint16_2: 0xf00f,
                uint24_1: 0x080808,
                uint24_2: 0xabbacd,
                uint32_1: 0x0badbeef,
                uint32_2: 0xbadbeeff,
            };

            var buffer = unsignedSpec.write( obj );

            var newObj = {};
            unsignedSpec.read( buffer, newObj );

            newObj.uint8_1.should.equal( obj.uint8_1 );
            newObj.uint8_2.should.equal( obj.uint8_2 );
            newObj.uint16_1.should.equal( obj.uint16_1 );
            newObj.uint16_2.should.equal( obj.uint16_2 );
            newObj.uint24_1.should.equal( obj.uint24_1 );
            newObj.uint24_2.should.equal( obj.uint24_2 );
            newObj.uint32_1.should.equal( obj.uint32_1 );
            newObj.uint32_2.should.equal( obj.uint32_2 );

        });

        it( 'should write signed numbers correctly', function() {
            
            var obj = {
                int8_1: 0x01,
                int8_2: -1,
                int16_1: 0x1001,
                int16_2: -1,
                int32_1: 0x10000001,
                int32_2: -1
            };

            var buffer = signedSpec.write( obj );

            var newObj = {};
            signedSpec.read( buffer, newObj );

            newObj.int8_1.should.equal( obj.int8_1 );
            newObj.int8_2.should.equal( obj.int8_2 );
            newObj.int16_1.should.equal( obj.int16_1 );
            newObj.int16_2.should.equal( obj.int16_2 );
            newObj.int32_1.should.equal( obj.int32_1 );
            newObj.int32_2.should.equal( obj.int32_2 );

        });

        it( 'should write variable length fields', function() {

            var obj = {
                var8: crypto.pseudoRandomBytes( 0x10 ),
                var16: crypto.pseudoRandomBytes( 0x100 ),
                var24: crypto.pseudoRandomBytes( 0x100 ),
                var32: crypto.pseudoRandomBytes( 0x100 )
            };

            var buffer = variableSpec.write( obj );

            var newObj = {};
            variableSpec.read( buffer, newObj );

            newObj.var8.should.deep.equal( obj.var8 );
            newObj.var16.should.deep.equal( obj.var16 );
            newObj.var24.should.deep.equal( obj.var24 );
            newObj.var32.should.deep.equal( obj.var32 );
        });

        it( 'should write byte array', function() {

            var bytes1 = new Buffer([ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 ]);
            var bytes2 = new Buffer([ 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00 ]);

            var obj = {
                bytes1: bytes1,
                bytes2: bytes2
            };
            var buffer = bytesSpec.write( obj );

            buffer.should.deep.equal( Buffer.concat([ bytes1, bytes2 ]) );
        });

        it( 'should write custom data', function() {


            var obj = { custom: [ 0x01, 0x03, 0x05 ] };
            var buffer = customSpec.write( obj );

            buffer.should.deep.equal( new Buffer([ 0x01, 0x03, 0x05, 0x00 ]) );
        });

        it( 'should write nested data', function() {

            var range = new VersionRange({
                min: new Version({ major: 0xff, minor: 0x88 }),
                max: new Version({ major: 0x00, minor: 0xff })
            });

            var buffer = range.spec.write( range );

            buffer.should.deep.equal( new Buffer([ 0xff, 0x88, 0x00, 0xff ]) );

        });

        it( 'should write advanced variable data', function() {

            var obj = {
                var8uint16: [ 0x1001, 0xf00f ],
                var8version: [
                    new Version({ major: 0x01, minor: 0x10 }),
                    new Version({ major: 0x10, minor: 0x01 })
                ],
                var8var8Version: [
                    [ new Version({ major: 0x01, minor: 0x02 }) ],
                    [ new Version({ major: 0x01, minor: 0x02 }),
                        new Version({ major: 0x01, minor: 0x02 }) ],
                    [ new Version({ major: 0x03, minor: 0x04 }) ]
                ]
            };

            var buffer = advancedVariableSpec.write( obj );

            buffer.should.deep.equal( new Buffer([
                0x04, 0x10, 0x01, 0xf0, 0x0f,
                0x04, 0x01, 0x10, 0x10, 0x01,
                0x0b,
                    0x02, 0x01, 0x02,
                    0x04, 0x01, 0x02, 0x01, 0x02,
                    0x02, 0x03, 0x04 ]) );
        });
    });
});

