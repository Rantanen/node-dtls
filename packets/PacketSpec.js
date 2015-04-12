
"use strict";

var BufferReader = require( '../BufferReader' );
var BufferBuilder = require( '../BufferBuilder' );

var PacketSpec = function( spec ) {

    // Normalise input parameter
    this.spec = [];
    for( var s in spec ) {
        var item = PacketSpec.normalize( spec[s] );

        this.spec.push( item );
    }
};

PacketSpec.normalize = function( item ) {

    // Normalize { name: type } -> { name: name, type: type }
    if( typeof( item ) === 'object' ) {
        var keys = Object.keys( item );
        if( keys.length === 1 ) {
            item = {
                name: keys[0],
                type: item[ keys[0] ]
            };
        }
    } else if( typeof( item ) === 'string' ||
        ( item.prototype && item.prototype.spec ) ) {

        item = { name: '_', type: item };
    }

    if( item.type && typeof( item.type ) === 'string' )
        item.type = item.type.toLowerCase();

    var hasValidType = item.type &&
        ( ( item.type.prototype && item.type.prototype.spec ) ||
            types[ item.type ] );
    var hasReadWrite = item.read && item.write;

    if( !( hasValidType || hasReadWrite ) ) {
        throw new Error( 'PacketSpec must have either a valid type or read/write functions, field: ' + item.name );
    }

    if( item.itemType )
        item.itemType = PacketSpec.normalize( item.itemType );

    return item;
};

PacketSpec.prototype.read = function( reader, obj ) {

    if( reader instanceof Buffer )
        reader = new BufferReader( reader );

    for( var s in this.spec ) {
        var item = this.spec[s];

        // Finally assign the value.
        obj[ item.name ] = PacketSpec.readItem( reader, item );
    }

    return reader.remaining();
};

PacketSpec.prototype.write = function( obj ) {

    var builder = new BufferBuilder();

    for( var s in this.spec ) {
        var item = this.spec[s];
        var field = obj[ item.name ];

        PacketSpec.writeItem( builder, item, field, obj );
    }

    return builder.getBuffer();
};

PacketSpec.readItem = function( reader, item, obj ) {

    // Resolve the function used to read the value.
    var readerFunc = null;
    if( item.read ) {

        return item.read.call( obj, reader );

    } else if( item.type.prototype && item.type.prototype.spec ) {

        var spec = item.type.prototype.spec;
        var newObj = new item.type();
        spec.read( reader, newObj );
        return newObj;

    } else {

        // Reader function not specified explicitly. Read the value type.
        var typeFunc = types[ item.type ];

        // Check the type specification type
        if( typeof( typeFunc ) === 'string' ) {

            // strings refer to data types as defined in BufferReader/-Builder
            return reader[ 'read' + typeFunc ]();

        } else {

            // objects contain read/write methods. Use the read method.
            return typeFunc.read.call( obj, reader, item );
        }
    }
};

PacketSpec.writeItem = function( builder, item, field, obj ) {

    // Resolve the function used to write the value.
    var writerFunc = null;
    if( item.write ) {

        writerFunc = item.write.call( obj, builder, field  );

    } else if( item.type.prototype && item.type.prototype.spec ) {

        var spec = item.type.prototype.spec;
        builder.writeBytes( spec.write( field ) );

    } else {

        // Reader function not specified explicitly. Read the value type.
        var typeFunc = types[ item.type ];

        // Check the type specification type
        if( typeof( typeFunc ) === 'string' ) {

            // strings refer to data types as defined in BufferReader/-Builder
            builder[ 'write' + typeFunc ]( field );

        } else {

            // objects contain read/write methods. Use the write method.
            typeFunc.write.call( obj, builder, field, item );
        }
    }
};

var types = {
    uint8: 'UInt8',
    uint16: 'UInt16BE',
    uint24: 'UInt24BE',
    uint32: 'UInt32BE',
    int8: 'Int8',
    int16: 'Int16BE',
    int32: 'Int32BE',
    float: 'FloatBE',
    double: 'DoubleBE',
    var8: {
        read: constructVariableLengthRead( 8 ),
        write: constructVariableLengthWrite( 8 ),
    },
    var16: {
        read: constructVariableLengthRead( 16 ),
        write: constructVariableLengthWrite( 16 ),
    },
    var24: {
        read: constructVariableLengthRead( 24 ),
        write: constructVariableLengthWrite( 24 ),
    },
    var32: {
        read: constructVariableLengthRead( 32 ),
        write: constructVariableLengthWrite( 32 ),
    },
    bytes: {
        read: function( reader, type ) {
            return reader.readBytes( type.size );
        },
        write: function( builder, value, type ) {
            builder.writeBytes( value.slice( 0, type.size ) );
        }
    },
};

function constructVariableLengthRead( length ) {

    // If this is multi-byte read, specify Big endian format.
    if( length > 8 ) length = length + 'BE';

    return function( reader, type ) {
        var dataLength = reader[ 'readUInt' + length ]();

        if( !type.itemType ) {
            return reader.readBytes( dataLength );
        } else {
            var arr = [];
            var startOffset = reader.offset;
            while( reader.offset < startOffset + dataLength ) {
                arr.push( PacketSpec.readItem( reader, type.itemType ) );
            }
            return arr;
        }
    };
}

function constructVariableLengthWrite( length ) {

    // If this is multi-byte read, specify Big endian format.
    if( length > 8 ) length = length + 'BE';

    return function( builder, value, type ) {

        if( !type.itemType ) {
            builder[ 'writeUInt' + length ]( value.length );
            builder.writeBytes( value );
        } else {

            var arrayBuilder = new BufferBuilder();
            for( var i = 0; i < value.length; i++ ) {
                PacketSpec.writeItem( arrayBuilder, type.itemType, value[i], this );
            }

            var arrayBuffer = arrayBuilder.getBuffer();
            builder[ 'writeUInt' + length ]( arrayBuffer.length );
            builder.writeBytes( arrayBuffer );
        }
    };
}

module.exports = PacketSpec;
