
"use strict";

var BufferReader = function( buffer ) {
    this.buffer = buffer;
    this.offset = 0;
};

BufferReader.prototype.readUInt24BE = function( offset ) {
    return ( this.readUInt8( offset ) << 16 ) + this.readUInt16BE();
};
BufferReader.prototype.readUInt24LE = function( offset ) {
    return this.readUInt8( offset ) + ( this.readUInt16LE() << 8 );
};

BufferReader.prototype.readBytes = function( size ) {
    var value = this.buffer.slice( this.offset, this.offset + size );
    this.offset += size;
    return value;
};

BufferReader.prototype.seek = function( pos ) {
    this.offset = pos;
};

BufferReader.prototype.remaining = function() {
    return this.buffer.slice( this.offset );
};

BufferReader.prototype.available = function() {
    return this.offset < this.buffer.length;
};

var makeDelegate = function( type, size ) {
    if( type instanceof Object ) {
        return Object.keys( type ).forEach( function( k ) {
            makeDelegate( k, type[k] );
        });
    }

    BufferReader.prototype[ 'read' + type ] = function( offset ) {
        if( offset !== undefined )
            this.offset = offset;

        var value = this.buffer[ 'read' + type ]( this.offset );
        this.offset += size;
        return value;
    };
};

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
};

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

module.exports = BufferReader;
