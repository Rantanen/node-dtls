
"use strict";

var should = require( 'chai' ).should();

var crypto = require( 'crypto' );
var constants = require( 'constants' );
var fs = require( 'fs' );

var ClientHandshakeHandler = require( '../ClientHandshakeHandler' );
var SecurityParameterContainer = require( '../SecurityParameterContainer' );
var dtls = require( '../dtls' );
var packets = require( '../packets' );
var CipherInfo = require( '../CipherInfo' );
var KeyContext = require( '../KeyContext' );
var prf = require( '../prf' );

describe( 'ClientHandshakeHandler', function() {

    var versions = {
        '1.2': {
            major: ~1,
            minor: ~2
        },
        '1.0': {
            major: ~1,
            minor: ~0
        }
    };

    for( var v in versions ) describe( 'DTLS v' + v, function() {

        var ver = versions[v];
        var version = new packets.ProtocolVersion( ver.major, ver.minor );

        describe( 'send_clientHello', function() {

            it( 'should send ClientHello', function( done ) {

                var parameters = new SecurityParameterContainer();
                var handshakeHandler = new ClientHandshakeHandler( parameters );
                handshakeHandler.version = version;

                handshakeHandler.onSend = function( msgs ) {

                    msgs.should.have.length( 1 );

                    var msg = msgs[0];

                    msg.msgType.should.equal( dtls.HandshakeType.clientHello );
                    msg.messageSeq.should.equal( 0 );
                    msg.fragmentOffset.should.equal( 0 );
                    msg.length.should.equal( msg.body.length );

                    var clientHello = new packets.ClientHello( msg.body );

                    clientHello.clientVersion.major.should.equal( ver.major );
                    clientHello.clientVersion.minor.should.equal( ver.minor );

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
                handshakeHandler.setResponse( null );
            });

            it( 'should create new SecurityParameter', function() {

                var parameters = new SecurityParameterContainer();
                var handshakeHandler = new ClientHandshakeHandler( parameters );
                handshakeHandler.onSend = function() {};

                should.not.exist( parameters.pending );

                handshakeHandler.send_clientHello();
                handshakeHandler.setResponse( null );

                should.exist( parameters.pending );
                parameters.pending.epoch.should.equal( parameters.current + 1 );
            });
        });

        describe( '#handle_helloVerifyRequest()', function() {

            it( 'should cause ClientHello', function() {

                var parameters = new SecurityParameterContainer();
                var handshakeHandler = new ClientHandshakeHandler( parameters );

                var cookie = new Buffer( 20 );

                var action = handshakeHandler.handle_helloVerifyRequest({
                    body: new packets.HelloVerifyRequest({
                            serverVersion: new packets.ProtocolVersion({
                                major: ver.major, minor: ver.minor }),
                            cookie: cookie
                        }).getBuffer()
                    });

                action.should.equal( handshakeHandler.send_clientHello );
                handshakeHandler.setResponse( null );

                handshakeHandler.cookie.should.deep.equal( cookie );
            });
        });

        describe( '#handle_serverHello()', function() {

            it( 'should set the parameters', function() {

                var parameters = new SecurityParameterContainer();
                var handshakeHandler = new ClientHandshakeHandler( parameters );

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

                // ServerHello alone doesn't result in action. Client should
                // wait for Certificate and HelloDone.
                should.not.exist( action );

                param.version.major.should.equal( ver.major );
                param.version.minor.should.equal( ver.minor );
                param.serverRandom.should.deep.equal( random.getBuffer() );
                param.compressionMethod.should.equal( 0 );

                setFrom.should.be.true;
            });
        });

        describe( '#handle_certificate()', function() {

            it( 'should store certificate', function() {

                var parameters = new SecurityParameterContainer();
                var handshakeHandler = new ClientHandshakeHandler( parameters );

                var certificateList = [
                    crypto.pseudoRandomBytes( 1024 )
                ];

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

        describe( '#handle_serverHelloDone()', function() {

            it( 'should send pre-master key', function() {

                var clientRandom = crypto.pseudoRandomBytes( 16 );
                var serverRandom = crypto.pseudoRandomBytes( 16 );

                var parameters = new SecurityParameterContainer();
                var handshakeHandler = new ClientHandshakeHandler( parameters );
                var param = handshakeHandler.newParameters =
                    parameters.initNew( version );

                handshakeHandler.version = param.version = version;
                param.clientRandom = clientRandom;
                param.serverRandom = serverRandom;

                var action = handshakeHandler.handle_serverHelloDone({
                    body: new packets.ServerHelloDone().getBuffer()
                });

                should.exist( param.masterKey );
                should.exist( param.preMasterKey );
                action.should.equal( handshakeHandler.send_keyExchange );
                handshakeHandler.setResponse( null );
            });
        });

        describe( '#send_keyExchange()', function() {

            it( 'should send key', function( done ) {

                var parameters = new SecurityParameterContainer();
                var handshakeHandler = new ClientHandshakeHandler( parameters );
                var param = handshakeHandler.newParameters =
                    parameters.initNew( version );

                var clientRandom = new packets.Random();
                var serverRandom = new packets.Random();
                param.clientRandom = clientRandom.getBuffer();
                param.serverRandom = serverRandom.getBuffer();

                var preMasterKey = crypto.pseudoRandomBytes( 20 );
                param.calculateMasterKey( preMasterKey );

                var pem = fs.readFileSync( 'test/assets/certificate.pem' );
                var keyContext = new KeyContext({
                    key: pem,
                    cert: pem
                });

                param.preMasterKey = preMasterKey;
                handshakeHandler.certificate = keyContext.certificate;

                handshakeHandler.onSend = function( msgs ) {

                    msgs.should.have.length( 3 );

                    msgs[0].type.should.equal( dtls.MessageType.handshake );
                    msgs[1].type.should.equal( dtls.MessageType.changeCipherSpec );
                    msgs[2].type.should.equal( dtls.MessageType.handshake );

                    msgs[0].msgType.should.equal(
                        dtls.HandshakeType.clientKeyExchange );
                    msgs[2].msgType.should.equal(
                        dtls.HandshakeType.finished );

                    var keyExchange = new packets.ClientKeyExchange_rsa(
                            msgs[0].body );
                    var actualPreMaster = crypto.privateDecrypt({
                        key: keyContext.key,
                        padding: constants.RSA_PKCS1_PADDING
                    }, keyExchange.exchangeKeys );

                    actualPreMaster.should.deep.equal( preMasterKey );

                    msgs[1].value.should.equal( 1 );

                    // Pop the 'Finished' handshake off the params.
                    param.handshakeDigest.pop();
                    var digest = param.getHandshakeDigest();

                    var expected = prf( version )(
                        param.masterKey,
                        "client finished",
                        digest, 12 );

                    msgs[2].body.should.deep.equal( expected );

                    done();
                };

                var fragments = handshakeHandler.send_keyExchange();
                handshakeHandler.setResponse( null );
            });
        });
    });
});
