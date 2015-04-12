
node-dtls
=========
### DTLS implementation in JavaScript (Work in progress)

Datagram Transport Layer Security (DTLS) Protocol implementation for Node.js
written in JavaScript.

While Node.js still lacks support for DTLS protocol, this library attempts to
fix the issue. This is in no way a security implementation as it's main goal is
to allow using protocols that _require_ DTLS. While the library implements the
proper DTLS encryption and validation, there has been no effort to protect it
against well known TLS attacks.

#### Current state

Currently the library succeeds in performing DTLS 1.2 handshake in server role
and decrypts application data from the client.

There is no real API to work with so currently the library is of no real use.
This should change within the next week or two though. I believe most of the
hard work is done for a usable DTLS-server implementation.

- [x] DTLS 1.2 handshake in server role
  - [x] RSA master secret exchange
  - [x] Generate keying material
  - [x] Encrypt/Decrypt ciphertext
  - [x] Calculate HMAC
  - [x] Validate handshake with Finished messages
- [ ] Handle application data
  - [x] Receive and decrypt application data from the client
  - [ ] Encrypt and send application data to the client
    - Encryption/Decryption stuff should be in place already. API is missing.
- [ ] Proper API to handle sessions/messages outside the node-dtls internals.
  - Try to mimic tls/dgram APIs from Node
- [ ] DTLS 1.0 handshake in server role
  - There shouldn't be _too_ many changes. Main one is propably the PRF hash.
- [ ] Connect in client role
- [ ] Handle renegotiation
- [ ] Robustness
  - [x] Handshake reassembly/buffering/reordering
  - [ ] Handle alert-messages
  - [ ] Retransmission
  - [ ] Validate handshake state and expected messages
  
#### References

[Datagram Transport Layer Security Version 1.2, RFC 6347]
(https://tools.ietf.org/html/rfc6347)

[The Transport Layer Security (TLS) Protocol Version 1.2, RFC 5246]
(https://tools.ietf.org/html/rfc5246)
