
"use strict";

var BufferBuilder = function() {
    this.buffers = [];
};

BufferBuilder.prototype.writeUInt24BE = function( value, offset ) {
    this.writeUInt8( ( value & 0xff0000 ) >> 16, offset );
    this.writeUInt16BE( value & 0x00ffff );
};
BufferBuilder.prototype.writeUInt24LE = function( value, offset ) {
    this.writeUInt8( value & 0x0000ff, offset );
    this.writeUInt16LE( ( value & 0xffff00 ) >> 8 );
};

BufferBuilder.prototype.writeBytes = function( buffer, size ) {
    this.buffers.push( buffer.slice( 0, size ) );
};

BufferBuilder.prototype.getBuffer = function() {
    return Buffer.concat( this.buffers );
}

var makeDelegate = function( type, size ) {
    if( type instanceof Object ) {
        return Object.keys( type ).forEach( function( k ) {
            makeDelegate( k, type[k] );
        });
    }

    BufferBuilder.prototype[ 'write' + type ] = function( value ) {

        var buffer = new Buffer( size );
        buffer[ 'write' + type ]( value, 0 );
        this.buffers.push( buffer );
    };
}

var expandTypes = function( types /*, ... */ ) {

    for( var i = 1; i < arguments.length; i++ ) {
        var patterns = arguments[i];

        var newTypes = [];
        for( var t in types ) {

            for( var p in patterns ) {
                newTypes[ patterns[p].replace( '*', t ) ] = types[t];
            }
        }
        types = newTypes;
    }

    return types;
}

// Types with Little and Big endian alternatives
makeDelegate(
    expandTypes( {
        Int16: 2,
        Int32: 4
    }, [ '*LE', '*BE' ], [ 'U*', '*' ] ) );

makeDelegate(
    expandTypes( {
        Int8: 1
    }, [ 'U*', '*' ] ) );

makeDelegate(
    expandTypes( {
        Float: 4,
        Double: 8
    }, [ '*LE', '*BE' ] ) );

module.exports = BufferBuilder;
module.exports = BufferBuilder;
