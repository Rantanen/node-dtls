
"use strict";

var should = require( 'chai' ).should();

var crypto = require( 'crypto' );
var fs = require( 'fs' );

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

                clientHello.random.getBuffer().should.deep.equal(
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

    describe( 'handle_serverHello', function() {

        it( 'should set the parameters', function() {

            var parameters = new SecurityParameterContainer();
            var handshakeHandler = new ClientHandshakeHandler( parameters );

            var version = new packets.ProtocolVersion( ~1, ~2 );
            var random = new packets.Random();
            var sessionId = crypto.pseudoRandomBytes( 16 );
            var cipherSuite = CipherInfo.TLS_RSA_WITH_AES_128_CBC_SHA;

            var param = handshakeHandler.newParameters =
                parameters.initNew( version );

            var setFrom = false;
            param.setFrom = function( suite ) {
                setFrom = true;
                suite.should.equal( cipherSuite );
            };

            var action = handshakeHandler.handle_serverHello({
                body: new packets.ServerHello({
                    serverVersion: version,
                    random: random,
                    sessionId: sessionId,
                    cipherSuite: cipherSuite.id,
                    compressionMethod: 0,
                    extensions: []
                }).getBuffer()
            });

            // ServerHello alone doesn't result in action. Client should wait
            // for Certificate and HelloDone.
            should.not.exist( action );

            param.version.major.should.equal( ~1 );
            param.version.minor.should.equal( ~2 );
            param.serverRandom.should.deep.equal( random.getBuffer() );
            param.compressionMethod.should.equal( 0 );

            setFrom.should.be.true;
        });
    });

    describe( 'handle_certificate', function() {

        it( 'should store certificate', function() {

            var parameters = new SecurityParameterContainer();
            var handshakeHandler = new ClientHandshakeHandler( parameters );

            var certificateList = [
                crypto.pseudoRandomBytes( 1024 )
            ];
                
            var version = new packets.ProtocolVersion( ~1, ~2 );
            var param = handshakeHandler.newParameters =
                parameters.initNew( version );

            var action = handshakeHandler.handle_certificate({
                body: new packets.Certificate({
                    certificateList: certificateList
                }).getBuffer()
            });

            // Certificate alone doesn't result in action. Client should wait
            // for HelloDone.
            should.not.exist( action );
            handshakeHandler.certificate.should.deep.equal( certificateList[0] );
        });
    });

    describe( 'handle_serverHelloDone', function() {

        it( 'should send pre-master key', function() {

            var parameters = new SecurityParameterContainer();
            var handshakeHandler = new ClientHandshakeHandler( parameters );
            var param = handshakeHandler.newParameters =
                parameters.initNew( version );

            var version = new packets.ProtocolVersion( ~1, ~2 );
            var clientRandom = crypto.pseudoRandomBytes( 16 );
            var serverRandom = crypto.pseudoRandomBytes( 16 );

            handshakeHandler.version = param.version = version;
            param.clientRandom = clientRandom;
            param.serverRandom = serverRandom;

            var action = handshakeHandler.handle_serverHelloDone({
                body: new packets.ServerHelloDone().getBuffer()
            });

            should.exist( param.masterKey );
            should.exist( param.preMasterKey );
            action.should.equal( handshakeHandler.send_keyExchange );
        });
    });
});
