
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.ClientHandshakeHandler' );
var crypto = require( 'crypto' );
var constants = require( 'constants' );

var dtls = require( './dtls' );
var HandshakeBuilder = require( './HandshakeBuilder' );
var CipherInfo = require( './CipherInfo' );
var prf = require( './prf' );
var Certificate = require( './Certificate' );

var DtlsHandshake = require( './packets/DtlsHandshake' );
var DtlsClientHello = require( './packets/DtlsClientHello' );
var DtlsHelloVerifyRequest = require( './packets/DtlsHelloVerifyRequest' );
var DtlsServerHello = require( './packets/DtlsServerHello' );
var DtlsCertificate = require( './packets/DtlsCertificate' );
var DtlsServerHelloDone = require( './packets/DtlsServerHelloDone' );
var DtlsClientKeyExchange_rsa = require( './packets/DtlsClientKeyExchange_rsa' );
var DtlsPreMasterSecret = require( './packets/DtlsPreMasterSecret' );
var DtlsChangeCipherSpec = require( './packets/DtlsChangeCipherSpec' );
var DtlsFinished = require( './packets/DtlsFinished' );
var DtlsProtocolVersion = require( './packets/DtlsProtocolVersion' );
var DtlsRandom = require( './packets/DtlsRandom' );
var DtlsExtension = require( './packets/DtlsExtension' );

/* Note the methods in this class aren't grouped with similar methods. Instead
 * the handle_ and send_ methods follow the logical order as defined in the
 * DTLS/TLS specs.
 */

/**
 * Implements the DTLS client handshake.
 */
var ClientHandshakeHandler = function( parameters, keyContext ) {

    this.parameters = parameters;
    this.handshakeBuilder = new HandshakeBuilder();

    this.cookie = new Buffer(0);
    this.certificate = null;

    // Handshake builder makes sure that the normal handling methods never
    // receive duplicate packets. Duplicate packets may mean that the last
    // flight of packets we sent got lost though so we need to handle these.
    this.handshakeBuilder.onRetransmission = this.retransmitLast.bind( this );
};

/**
 * Processes an incoming handshake message from the server.
 *
 * @param {DtlsPlaintext} message
 *      The TLS envelope containing the handshake message.
 */
ClientHandshakeHandler.prototype.process = function( message ) {

    // Enqueue the current handshake.
    var newHandshake = new DtlsHandshake( message.fragment );
    var newHandshakeName = dtls.HandshakeTypeName[ newHandshake.msgType ];
    log.info( 'Received handshake fragment; sequence:',
        newHandshake.messageSeq + ':' + newHandshakeName );
    this.handshakeBuilder.add( newHandshake );

    // Process available defragmented handshakes.
    var handshake = this.handshakeBuilder.next();
    while( handshake ) {
        var handshakeName = dtls.HandshakeTypeName[ handshake.msgType ];

        var handler = this[ 'handle_' + handshakeName ];
        if( !handler ) {
            log.error( 'Handshake handler not found for ', handshakeName );
            continue;
        }

        log.info( 'Processing handshake:',
            handshake.messageSeq + ':' + handshakeName );
        var action = this[ 'handle_' + handshakeName ]( handshake, message );

        // Digest this message after handling it.
        // This way the ClientHello can create the new SecurityParamters before
        // we digest this so it'll get digested in the correct context AND the
        // Finished message can verify its digest without counting itself in
        // it.
        //
        // TODO: Make sure 'message' contains the defragmented buffer.
        // We read the buffer in HandshakeBuilder anyway so there's no real
        // reason to call getBuffer() here.
        if( this.newParameters ) {
            this.newParameters.digestHandshake( handshake.getBuffer() );
        }

        // However to get the digests in correct order, the handle_ method
        // above couldn't have invoked the send_ methods as those take care of
        // digesting their own messages. So instead they returned the action
        // and we'll invoke them after the digest.
        if( action )
            action.call( this );

        handshake = this.handshakeBuilder.next();
    }
};

ClientHandshakeHandler.prototype.renegotiate = function() {
    this.send_clientHello();
};

/**
 * Sends the ServerHello message
 */
ClientHandshakeHandler.prototype.send_clientHello = function() {

    // TLS spec require all implementations MUST implement the
    // TLS_RSA_WITH_AES_128_CBC_SHA cipher.
    var cipher = CipherInfo.TLS_RSA_WITH_AES_128_CBC_SHA;

    var clientHello = new DtlsClientHello({
        clientVersion: new DtlsProtocolVersion({ major: ~1, minor: ~2 }),
        random: new DtlsRandom(),
        sessionId: new Buffer(0),
        cookie: this.cookie || new Buffer(0),
        cipherSuites: [ cipher.id ],
        compressionMethods: [ 0 ],

        // TODO: Remove the requirement for extensions. Currently packets with
        // 0 extensions will serialize wrong. I don't even remember which
        // extension this is. Maybe heartbeat? Whatever it is, we definitely do
        // not implement it. :)
        extensions: [
            new DtlsExtension({
                extensionType: 0x000f,
                extensionData: new Buffer([ 1 ])
            })
        ]
    });

    // Store more parameters.
    this.newParameters = this.parameters.initNew( clientHello.clientVersion );
    this.newParameters.isServer = false;
    this.newParameters.clientRandom = clientHello.random.getBytes();

    log.info( 'Sending ClientHello' );
    var handshakes = this.handshakeBuilder.createHandshakes([ clientHello ]);

    handshakes = handshakes.map( function(h) { return h.getBuffer(); });
    this.newParameters.digestHandshake( handshakes );

    var packets = this.handshakeBuilder.fragmentHandshakes( handshakes );

    this.setResponse( packets );
};

ClientHandshakeHandler.prototype.handle_helloVerifyRequest = function( handshake ) {
    var verifyRequest = new DtlsHelloVerifyRequest( handshake.body );
    this.cookie = verifyRequest.cookie;

    this.version = verifyRequest.serverVersion;

    return this.send_clientHello;
};

/**
 * Handles the ClientHello message.
 *
 * The message is accepted only if it contains the correct cookie. If the
 * cookie is wrong, we'll send a HelloVerifyRequest packet instead of
 * proceeding with the handshake.
 */
ClientHandshakeHandler.prototype.handle_serverHello = function( handshake, message ) {

    var serverHello = new DtlsServerHello( handshake.body );

    log.fine( 'ServerHello received. Server version:', 
        ~serverHello.serverVersion.major + '.' + 
        ~serverHello.serverVersion.minor );

    // TODO: Validate server version
    this.version = serverHello.serverVersion;
    this.newParameters.version = this.version;
    this.newParameters.serverRandom = serverHello.random.getBytes();
    var cipher = CipherInfo.get( serverHello.cipherSuite );
    this.newParameters.setFrom( cipher );
    this.newParameters.compressionMethod = serverHello.compressionMethod;

    if( !this.parameters.first.version )
        this.parameters.first.version = serverHello.serverVersion;

    this.setResponse( null );
};

ClientHandshakeHandler.prototype.handle_certificate = function( handshake, message ) {

    var certificate = new DtlsCertificate( handshake.body );

    // Just grab the first ceritificate ":D"
    this.certificate = certificate.certificateList[ 0 ];

    this.setResponse( null );
};

ClientHandshakeHandler.prototype.handle_serverHelloDone = function( handshake, message ) {

    log.info( 'Server hello done' );

    var preMasterKey = Buffer.concat([
        this.version.getBuffer(),
        crypto.randomBytes( 46 ) ]);

    this.newParameters.calculateMasterKey( preMasterKey );
    this.newParameters.preMasterKey = preMasterKey;

    this.newParameters.init();

    log.info( 'Returning', this.send_keyExchange );
    return this.send_keyExchange;
};

ClientHandshakeHandler.prototype.send_keyExchange = function() {

    log.info( 'Constructing key exchange' );

    var publicKey = Certificate.getPublicKeyPem( this.certificate );
    var exchangeKeys = crypto.publicEncrypt({
            key: publicKey,
            padding: constants.RSA_PKCS1_PADDING
        }, this.newParameters.preMasterKey );

    var keyExchange = new DtlsClientKeyExchange_rsa({
        exchangeKeys: exchangeKeys
    });
    var keyExchangeHandshake = this.handshakeBuilder.createHandshakes(
            keyExchange ).getBuffer();

    this.newParameters.digestHandshake( keyExchangeHandshake );
    this.newParameters.preMasterKey = null;

    var changeCipherSpec = new DtlsChangeCipherSpec({ value: 1 });

    var prf_func = prf( this.version );
    var verifyData = prf_func(
        this.newParameters.masterKey,
        "client finished",
        this.newParameters.getHandshakeDigest(),
        12
    );
    var finished = new DtlsFinished({ verifyData: verifyData });
    var finishedHandshake = this.handshakeBuilder.createHandshakes(
            finished ).getBuffer();
    this.newParameters.digestHandshake( finishedHandshake );

    var keyExchangeFragments = this.handshakeBuilder.fragmentHandshakes( keyExchangeHandshake );
    var finishedFragments = this.handshakeBuilder.fragmentHandshakes( finishedHandshake );

    var outgoingFragments = keyExchangeFragments;
    outgoingFragments.push( changeCipherSpec );
    outgoingFragments = outgoingFragments.concat( finishedFragments );

    this.setResponse( outgoingFragments );
};

/**
 * Handles the client Finished message.
 *
 * Technically there is a ChangeCipherSpec message between ClientKeyExchange
 * and Finished messages. ChangeCipherSpec isn't a handshake message though so
 * it never makes it here. That message is handled in the RecordLayer.
 */
ClientHandshakeHandler.prototype.handle_finished = function( handshake, message ) {

    var finished = new DtlsFinished( handshake.body );

    var prf_func = prf( this.version );

    var expected = prf_func(
        this.newParameters.masterKey,
        "server finished",
        this.newParameters.getHandshakeDigest(),
        finished.verifyData.length
    );

    if( !finished.verifyData.equals( expected ) ) {
        log.warn( 'Finished digest does not match. Expected:',
            expected,
            'Actual:',
            finished.verifyData );
        return;
    }

    this.setResponse( null );

    // The handle_ methods should RETURN the response action.
    // See the handle() method for explanation.
    return this.onHandshake();
};

/**
 * Sets the response for the last client message.
 *
 * The last flight of packets is stored so we can somewhat automatically handle
 * retransmission when we see the client doing it.
 */
ClientHandshakeHandler.prototype.setResponse = function( packets, done ) {
    this.lastFlight = packets;

    if( packets )
        this.onSend( packets, done );

    if( this.retransmitTimer )
        clearTimeout( this.retransmitTimer );

    this.retransmitTimer = setTimeout( function() {
        this.retransmitLast();
    }.bind( this ), 1000 );
};

/**
 * Retransmits the last response in case it got lost on the way last time.
 *
 * @param {DtlsPlaintext} message
 *      The received packet that triggered this retransmit.
 */
ClientHandshakeHandler.prototype.retransmitLast = function( message ) {

    if( this.lastFlight )
        this.onSend( this.lastFlight );

    this.retransmitTimer = setTimeout( function() {
        this.retransmitLast();
    }.bind( this ), 1000 );
};

module.exports = ClientHandshakeHandler;
