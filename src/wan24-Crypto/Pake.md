# PAKE

This is a Password Authenticated Key Exchange protocol, which uses symmetric 
cryptographic algorithms only.

In the following pseudo codes there are some functions used:

- MAC: Any MAC algorithm - first parameter is the data, second parameter the 
key
- KDF: Any KDF algorithm - first parameter is the key, second parameter the 
salt, third parameter is the return value length
- RND: A cryptographic random byte generator - first parameter is the return 
value length

It's possible to include any payload data (`payload`) which is required to 
process a signup/authentication at the server side.

## Client

At the client no informatiomation will be stored, since all information can be 
generated from a login username (`id`) and password (`key`):

```js
// Hide the raw ID as good as possible, and don't work with the raw data EVER again
key_mac = MAC(key, key)
identifier = MAC(id, key_mac, key_mac.Length)

// Ensure to NEVER use the raw key again
expanded_key = KDF(key, identifier, identifier.Length)

// Since the expanded key is an unshared secret, the auth_key can't be calculated on the server
auth_key = MAC(identifier, expanded_key)

// The secret needs to be stored at the server during signup, but won't be sent by the client for a later authentication
secret = MAC(expanded_key, auth_key)

// The key for a pseudo-signature
signature_key = KDF(auth_key, identifier, auth_key.Length)

// Random data ensures using a fresh session key with each key exchange
random = RND(auth_key.Length)

// "Sign" the data INCLUDING the secret
signature = MAC(random+payload+secret+identifier+auth_key, signature_key)

// This calculates the session key, which can be calculated by the server, too
session_key = MAC(random, MAC(signature_key, secret))
```

This needs to be done for the signup and each later authentication.

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
identity.secret = signup.secret
identity.signature_key = signature_key
```

Also the session key (`session_key`) is exchanged now.

**NOTE**: Instead of storing every value as it is, all values could be stored 
XORed in a single field. Anyway, in this case the `identifier` couldn't be 
used to load an identity record (this must be solved using another identifier 
then).

## Authentication

The client will send some information to the server (the `secret` is missing 
here, compared to the signup):

```js
auth.identifier = identifier
auth.auth_key = auth_key
auth.signature = signature
auth.payload = payload
auth.random = random
```

Then the server can validate the authentication data:

```js
// Calculate and validate the signature from mixed offline stored and received authentication data
signature = MAC(auth.random+auth.payload+identity.secret+auth.identifier+auth.auth_key, identity.signature_key)
auth.signature == signature

// Calculate and validate the signature key (KDF only after successful MAC validation, to prevent DoS!)
signature_key = KDF(auth.auth_key, auth.identity, auth.auth_key.Length)
signature_key == identity.signature_key

// Calculate the session key, which should be the same as the one the client calculated
session_key = MAC(auth.random, MAC(signature_key, identity.secret))
```

Also the session key (`session_key`) is exchanged now.

These information subsets are required to be combined for an authentication:

Client subset:
- `auth_key`
- `payload`
- `random`

Server subset:
- `secret`

The combination of all client authentication and server side identity data is 
enough to validate the client authentication data and calculate a shared 
session key which is based on the client generated random data.

## Advantages of PAKE wrapped by an asymmetric PFS protocol

- The client doesn't need to store anything
- The server will only store a small subset of the client information
- For authentication the client need to send only a subset of the required 
information
- The server can validate and authenticate by combining stored and received 
data subsets
- A MiM can't get enough data to figure out anything more than who 
authenticates
- The servers DBMS doesn't offer enough information to do anything
- Login username and password are never exposed anywhere and is also invisible 
to the server
- During authentication a calculated MAC must match, before a KDF generated 
sequence is being generated and compared to finalize an authentication, which 
protects from DoS using pure random data
- If the servers DBMS or the communication channel is broken (MiM), security 
still relies on the used MAC and KDF algorithms, where especially the KDF 
takes an important part at the end

## Disadvantages of this PAKE implementation

- A MiM which knows the server DBMS contents is able to reproduce client 
authentication information as he want (this would break the PAKE security)
- All communication must be wrapped using an asymmetric PFS protocol, because 
PAKE signup (especially!) and authentication data is still sensitive and 
shouldn't be exposed to any unauthorized party

## Usage thoughts

Authentication shouldn't rely on PAKE only: It should be seen as a single part 
of a larger authentication protocol, which ensures that the authentication 
doesn't only rely on a mathematical problem (which may be solvable using QBits 
already), as asymmetric algorithms from today do. The huge count of symmetric 
one-way algorithm usages extends an authentication with an amount of security, 
which noone really wants to miss.

Anyway, to benefit from PAKE as an additional security component, a session 
key could be a combination of an asymmetric exchanged session key with the 
PAKE exchanged session key. This would require the algorithms of both 
components to be broken in order to break in total - which is unlikely to 
happen (also in the long term).

It's also still a good idea to include multiple factors at last for a signup. 
An OTP, which was communicated using another channel, could be used as payload 
to validate a non-robot peer. Or a token, which is being used by authenticator 
apps.

And finally, don't miss to include and sign some important metrics into a 
handshake:

- UTC time code (to avoid replay attacks)
- Client meta data (signed from the server and validated by the client to 
disclose a MiM)

In a perfect world, the authentication protocol would use pre-shared keys, 
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

As algorithms for a full cipher suite I'd choose in 2023:

- CRYSTALS-Kyber (or FrodoKEM) for pre-shared and PFS keys and wrapping non-PQ 
algorithms
- ECDH (or DH) for wrapped pre-shared and PFS non-PQ keys
- CRYSTALS-Dilithium (or SPHINX+, or FALCON) for pre-shared signature keys and 
wrapping non-PQ algorithms
- ECDSA (or DSA; pre-shared) for wrapped non-PQ signing
- SHA-512
- HMAC-SHA-512
- PBKDF#2 or Argon2id
- PAKE (as I implemented it :)
- AES-256-GCM (with HMAC-SHA-256, or CBC with HMAC-SHA-512)

Having PQ in mind, PQ algorithms should always wrap non-PQ algorithms, while 
I'd consider existing common symmetric algorithms to be PQ-safe today and in 
the long term also, when using 512 bit variants (or 256 in case of AES). For 
any key and salt sizes, I'd follow the up to date recommendations (OWASP).

All in all there is a huge potential for storing informations in a "secure" 
way, when playing with the PAKE values, which are stored at the server and 
being sent by the client. With a little creativity, values can be stored in a 
way that would bring tears into a hackers eyes for sure, and make the server 
become a no longer interesting target for hacking attacks, as long as the PFS 
protocol and the communication channels are safe.
