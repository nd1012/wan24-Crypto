# PAKE

This is a Password Authenticated Key Exchange protocol, which uses symmetric 
cryptographic algorithms only. Messages are required to be exchanged wrapped 
by a PFS protocol. All used/produced/communicated data IS sensitive!

In the following pseudo codes there are some functions used:

- MAC: Any MAC algorithm - first parameter is the data, second parameter the 
key (HMAC-SHA-512 for example)
- KDF: Any KDF algorithm - first parameter is the key, second parameter the 
salt, third parameter is the return value length (PBKDF#2 for example)
- RND: A cryptographic random byte generator - first parameter is the return 
value length
- ASSERT: Fails, if the expression (first parameter) resolves to `false`

It's possible to include any payload data (`payload`) which is required to 
process a signup/authentication at the server side. It'd be possible to 
encrypt the payload data using the pre-calculated PAKE session key, when 
changing the PAKE algorithm - don't do it! If you want to encrypt the payload, 
use another key - `signature_key` could be an usable candidate, if you'd like 
to use PAKE related values only, and early decryption of the payload is 
required.

**WARNING**: Since all symmetric algorithms can be attacked using brute force, 
the length of the used symmetric algorithms output is important: The longer 
the output, the more secure is the whole PAKE process. Because symmetric 
algorithms which produce 512 bit (64 byte) output are quiet fast, you 
shouldn't have to think about reducing the lenght by using other (faster) 
algorithms for saving bandwidth, computing resources or memory.

## Client

At the client no information will be stored, since all information can be 
generated from a login username (`id`) and password (`key`):

```js
// Hide the raw ID as good as possible, and DO NOT work with the raw data EVER again
identifier = MAC(id, MAC(key, key))

// Ensure to NEVER use the raw key again
expanded_key = KDF(key, identifier, identifier.length)

// Since the expanded_key is an unshared secret, the auth_key can't be calculated on the server
auth_key = MAC(identifier, expanded_key)

// The secret needs to be stored at the server during signup, but won't be sent by the client for a later authentication
secret = MAC(expanded_key, auth_key)

// The key for a pseudo-signature (won't be sent to the server, but will be calculated there, too)
signature_key = KDF(auth_key, secret, auth_key.length)

// Random data ensures using a fresh session key with each key exchange
random = RND(auth_key.length)

// "Sign" the data INCLUDING the secret
signature = MAC(random+payload+secret+identifier+auth_key, signature_key)

// This calculates the session key, which can be calculated by the server, too
session_key = MAC(random, MAC(signature_key, secret))
```

This needs to be done for the signup and each later authentication.

**CAUTION**: Avoid to store any of the used or calculated values at the client 
side! If your app requires to store the information, ensure they're stored 
encrypted and the used encryption key is secured using a TPM hardware at last.

## Signup

The client will send some information to the server for a signup:

```js
signup.identifier = identifier
signup.secret = secret
signup.auth_key = auth_key
signup.signature = signature
signup.payload = payload
signup.random = random
```

The server will validate the received data (by calculating the 
`signature_key` again) and store only some information:

```js
identity.identifier = signup.identifier
identity.secret = signup.secret ^ signup.auth_key
identity.signature_key = signature_key
```

**NOTE**: The `^` character is used as XOR operator here.

**CAUTION**: `identity.secret` and `identity.signature_key` should be stored 
encrypted! Ensure the used encryption key is secured using a TPM hardware at 
last.

Also the session key (`session_key`) is exchanged now.

## Authentication

The client will send some information to the server (the `secret` is missing 
here, compared to the signup, and also the original value of `auth_key` is 
hidden):

```js
auth.identifier = identifier
auth.auth_key = auth_key ^ MAC(random, signature_key)
auth.signature = signature
auth.payload = payload
auth.random = random
```

Then the server can validate the authentication data:

```js
// Extract auth_key and secret
auth_key = auth.auth_key ^ MAC(auth.random, identity.signature_key)
secret = identity.secret ^ auth_key

// Calculate and validate the signature from mixed offline stored and received authentication data
signature = MAC(auth.random+auth.payload+secret+auth.identifier+auth_key, identity.signature_key)
ASSERT(auth.signature == signature)

// Calculate and validate the signature key (KDF only after successful MAC validation, to prevent DoS!)
signature_key = KDF(auth_key, secret, auth_key.length)
ASSERT(signature_key == identity.signature_key)

// Calculate the session key, which should then be the same as the one the client calculated
session_key = MAC(auth.random, MAC(signature_key, secret))
```

Also the session key (`session_key`) is exchanged now.

## Advantages of PAKE wrapped by an asymmetric PFS protocol

- The client doesn't need to store anything
- The server will only store a small subset of the client information
- For authentication the client need to send only a subset of the required 
information
- The server can validate and authenticate by combining stored and received 
data subsets
- A MiM can't get enough data to figure out anything more than who 
authenticates
- The servers DBMS doesn't offer enough information to do anything (if values 
have been stored properly)
- Login username and password are never exposed anywhere and is also invisible 
to the server (!)
- During authentication a calculated MAC must match, before a KDF generated 
sequence is being generated and compared to finalize an authentication, which 
protects from DoS using pure random data
- If the servers DBMS or the communication channel is broken (MiM), security 
still relies on the used MAC and KDF algorithms, where especially the KDF 
takes an important part at the end

## Disadvantages of this PAKE implementation

- All communication must be wrapped using an asymmetric PFS protocol, because 
PAKE signup (especially!) and authentication data is still sensitive and 
shouldn't be exposed to any unauthorized party (for this a pre-shared key is 
required)

## Usage thoughts

Authentication shouldn't rely on PAKE only: It should be seen as a single part 
of a larger authentication protocol, which ensures that the authentication 
doesn't only rely on a mathematical problem (which may be solvable using QBits 
already), as common asymmetric algorithms from today do. The huge count of 
symmetric one-way algorithm usages extends an authentication with an amount of 
security, which noone really wants to miss.

Anyway, to benefit from PAKE as an additional security component, a session 
key could be a combination of an asymmetric exchanged session key with the 
PAKE exchanged session key. This would require the algorithms of both 
components to be broken in order to break the security in total - which is 
unlikely to happen (also in the long term).

It's also still a good idea to include multiple factors at last for a signup. 
An OTP, which was communicated using another channel, could be used as payload 
to validate a non-robot peer, or to add some independent communicated secret 
to the final session key.

And finally, don't miss to include and sign some important metrics into a 
handshake:

- UTC time code (to avoid replay attacks)
- Client meta data (signed from the server and validated by the client to 
disclose a MiM)

Since this PAKE implementation uses KDF, it's not designed for a secure AND 
fast key exchange, which could be automatted. It's more a signup and login 
helper, which exchanges a session key, but protects against brute force and 
DoS attacks (depending on the servers additional security issue handling 
algorithms) - not usable for a fast key exchange, where the speed is 
important. Once a session key was exchanged, the connection should be kept 
alive as long as possible and required. However, a periodical change of the 
session key with another embedded key exchange can't be a mistake.

This PAKE implementation is designed to protect the communicated and stored 
information as good as possible. Finally the security relies on the security 
of the server encryption key, which is used to encrypt the stored data. As 
long as this key is secure, a DBMS breach or a MiM or DoS attack wouldn't 
affect the client/server authentication security. Of course a required 
reaction to any breach would be to exchange the servers encryption key, and a 
fresh signup would be required in case of a MiM attack, too. If all data was 
handled as recommended in this document, even a breach of the DBMS combined 
with a successful MiM attack wouldn't break the authentication security, as 
long as the servers encryption key wasn't breached, too. Only a compromised 
client would break the authentication security, if an attacker was able to 
observe the used `id` and `key`, or the calculated PAKE values during signup 
or creating an authentication message.

The signup message is a critical part of this PAKE implementations security, 
because all PAKE values which can be used to perform a client authentication 
have to be sent insecure to the server. So the security relies fully on the 
wrapping PFS protocol, and the pre-shared key (if any). It's very important to 
ensure the signup communication is as secure as possible, and don't care about 
performance at that time! Use multiple factors for calculating a session key.

Anyway, if a fast authenticated messaging (UDP protocol) is required, PAKE 
client and server values may life longer within memory, as long as the server 
expects a client to send authenticated messages in a short term. The session 
key of the initial authentication could be used to encrypt all followup 
messages, while each followup message could encrypt a payload for a second 
time, using an embedded PAKE authentication. Fast PAKE authentication wouldn't 
use KDF, but the initial authentication should be performed as usual 
(including KDF).

In a perfect world, a TCP authentication protocol would use pre-shared keys, 
which could then look like this:

Client:
- Creates an asymmetric PFS key to calculate a key using the pre-shared 
servers public key (this is a temporary session key)
- The asymmetric public PFS key will be sent to the server
- The PAKE data will be send to the server encrypted using the calculated key
- Signs the handshake data using his pre-shared asymmetric public key, and 
encrypts the signature using a session key, which is a combination of the 
calculated key and the PAKE exchanged key (this is a temporary session key, 
too)

Server:
- Calculates a key using the clients asymmetric public PFS key and his 
asymmetric private key
- Calculates the PAKE session key and combines it with the previously 
calculated key
- Decrypts the client signature and validates it with the pre-shared 
asymmetric public key of the client
- Creates an asymmetric PFS key and uses it with the asymmetric public PFS key 
of the client to calculate a key and combine it with the PAKE exchanged key 
(this is the finally exchanged session key)
- Sends the asymmetric public PFS key encrypted with the symmetric handshake 
key which is known at the client already
- Creates a signature of the client handshake data, combined with his 
asymmetric public PFS key, and sends it encrypted with the session key

Client:
- Calculates the session key using his asymmetric private PFS key
- Decrypts and validates the server signature

Of course this workflow is still missing time offset validation, hammering 
protection, etc. - but it shows a possible combination of asymmetric PFS with 
symmetric PAKE, which I'd call "secure" in these days (based on the chosen 
underlying algorithms, of course).

Using PAKE it's also possible to process a single-directional channel 
communication, where the client does send payload encrypted using the PAKE 
key. The server wouldn't need to answer such a message, which could be a 
simple UDP packet for that reason.

As algorithms for a full cipher suite I'd choose in 2023:

- CRYSTALS-Kyber (or FrodoKEM) for pre-shared and PFS keys and wrapping non-PQ 
algorithms
- ECDH (or DH) for wrapped pre-shared and PFS non-PQ keys
- CRYSTALS-Dilithium (or SPHINX+, or FALCON) for pre-shared signature keys and 
wrapping non-PQ algorithms
- ECDSA (or DSA; pre-shared) for wrapped non-PQ signing
- SHA-384 (or SHA-512, depending on the purpose)
- HMAC-SHA-512
- PBKDF#2 or Argon2id
- PAKE (as I implemented it :)
- AES-256-GCM (with 128 bit MAC, or CBC with HMAC-SHA-512)

Having PQ in mind, PQ algorithms should always wrap non-PQ algorithms, while 
I'd consider existing common symmetric algorithms to be PQ-safe today and in 
the long term also, when using 512 bit variants (or 256 in case of AES). For 
any key and salt sizes, I'd follow the up to date recommendations (OWASP).
