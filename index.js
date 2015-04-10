

var DtlsSocket = require( './DtlsSocket' );

module.exports = {
    DtlsSocket: DtlsSocket,

    createSocket: function( options, callback ) {

        var dgram = require( 'dgram' );

        var dgramSocket = dgram.createSocket( options );
        var dtlsSocket = new DtlsSocket( dgramSocket );

        if( callback )
            dglsSocket.on( 'message', callback );

        return dtlsSocket;
    }
}
