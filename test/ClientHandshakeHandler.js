
"use strict";

var should = require( 'chai' ).should();

var ClientHandshakeHandler = require( '../ClientHandshakeHandler' );
var SecurityParameterContainer = require( '../SecurityParameterContainer' );
var dtls = require( '../dtls' );
var packets = require( '../packets' );
var CipherInfo = require( '../CipherInfo' );

describe( 'ClientHandshakeHandler', function() {

    describe( 'send_clientHello', function() {

        it( 'should send ClientHello', function( done ) {

            var parameters = new SecurityParameterContainer();
            var handshakeHandler = new ClientHandshakeHandler( parameters );

            handshakeHandler.onSend = function( msgs ) {

                msgs.should.have.length( 1 );

                var msg = msgs[0];

                msg.msgType.should.equal( dtls.HandshakeType.clientHello );
                msg.messageSeq.should.equal( 0 );
                msg.fragmentOffset.should.equal( 0 );
                msg.length.should.equal( msg.body.length );

                var clientHello = new packets.ClientHello( msg.body );

                clientHello.clientVersion.major.should.equal( ~1 );
                clientHello.clientVersion.minor.should.equal( ~2 );

                clientHello.random.getBytes().should.deep.equal(
                    parameters.parameters[1].clientRandom );

                clientHello.sessionId.should.have.length( 0 );
                clientHello.cookie.should.have.length( 0 );

                clientHello.cipherSuites.should.deep.equal([
                    CipherInfo.TLS_RSA_WITH_AES_128_CBC_SHA.id ]);
                clientHello.compressionMethods.should.deep.equal([0]);

                // Extensions not handled correctly at the moment.
                // clientHello.extensions.should.have.length( 0 );

                done();
            };

            handshakeHandler.send_clientHello();
        });

        it( 'should create new SecurityParameter', function() {

            var parameters = new SecurityParameterContainer();
            var handshakeHandler = new ClientHandshakeHandler( parameters );
            handshakeHandler.onSend = function() {};

            should.not.exist( parameters.pending );

            handshakeHandler.send_clientHello();

            should.exist( parameters.pending );
            parameters.pending.epoch.should.equal( parameters.current + 1 );
        });
    });

    describe( 'handle_helloVerifyRequest', function() {

        it( 'should cause ClientHello', function() {

            var parameters = new SecurityParameterContainer();
            var handshakeHandler = new ClientHandshakeHandler( parameters );

            var cookie = new Buffer( 20 );

            var action = handshakeHandler.handle_helloVerifyRequest({
                body: new packets.HelloVerifyRequest({
                        serverVersion: new packets.ProtocolVersion({
                            major: ~1, minor: ~2 }),
                        cookie: cookie
                    }).getBuffer()
                });

            action.should.equal( handshakeHandler.send_clientHello );

            handshakeHandler.cookie.should.deep.equal( cookie );
            handshakeHandler.version.major.should.equal( ~1 );
            handshakeHandler.version.minor.should.equal( ~2 );
        });
    });
});
