# wan24-Crypto

This library exports a generic high level crypto API, which allows to use an 
implemented cryptographic algorithm to be applied using a simple interface. It 
also implements abstract and configurable RNG handling, which uses a local 
(CS)RNG entropy source, if not overridden and extended with a customized RNG 
algorithm, which may use a physical entropy source, too.

Per default these cryptographic algorithms are implemented:

| Usage | Algorithm |
| --- | --- |
| **Hashing** | MD5 |
| | SHA-1 |
| | SHA-256 |
| | SHA-384 |
| | SHA-512 |
| **MAC** | HMAC-SHA-1 |
|  | HMAC-SHA-256 |
|  | HMAC-SHA-384 |
|  | HMAC-SHA-512 |
| **Symmetric encryption** | AES-256-CBC (ISO10126 padding) |
| **Asymmetric keys** | Elliptic Curve Diffie Hellman |
|  | Elliptic Curve DSA (RFC 3279 signatures) |
| **KDF key stretching** | PBKDF#2 (250,000 iterations per default) |

These elliptic curves are supported at present:

- secp256r1
- secp384r1
- secp521r1

The number of algorithms can be extended easy, a bunch of additional libraries 
implementing more algorithms (and probably more elliptic curves) will follow 
soon.

The goals of this library are:

- Make a choice being a less torture
- Make a complex thing as easy as possible

Implementing (new) cryptographic algorithms into (existing) code can be 
challenging. `wan24-Crypto` tries to make it as easy as possible, while the 
API is still complex due to the huge number of options it offers. Please see 
the [Wiki](https://github.com/nd1012/wan24-Crypto/wiki) for examples of the 
most common use cases, which cover:

- Simple encryption using a password
- Advanced encryption using a private PFS key
- Advanced encryption using a private PFS key and hybrid key exchange
- Advanced encryption using a peers public key
- Advanced encryption using a peers public key and hybrid key exchange

For more examples please open an 
[issue](https://github.com/nd1012/wan24-Crypto/issues/new) - I'd be glad to 
help! If you've found a security issue, please report it private.

**NOTE**: The cipher output of this library may include a header, which can't 
(yet) be interpreted by any third party vendor code (which is true especially 
if the raw data was compressed before encryption, which is the default). That 
means, a cipher output of this library can't be decrypted with a third party 
crypto library, even this library implements standard cryptographic algorithms.

Using this library for a cipher which has to be exchanged with a third party 
application, which relies on working with standard crypto algorithm output, is 
not recommended - it may not work!

Anyway, this library should be a good choice for isolated use within your 
application(s), if want to avoid a hussle with implementing newer crypto 
algorithms.

## How to get it

This library is available as 
[NuGet package](https://www.nuget.org/packages/wan24-Crypto/).

These extension NuGet packages are available:

- [wan24-Crypto-BC (adopts post quantum algorithms from Bouncy Castle)](https://www.nuget.org/packages/wan24-Crypto-BC/)
- [wan24-Crypto-NaCl (adopts the Argon2id KDF algorithm from NSec)](https://www.nuget.org/packages/wan24-Crypto-NaCl/)

## Usage

### Hashing

```cs
byte[] hash = rawData.Hash();
```

The default hash algorithm ist SHA512.

### MAC

```cs
byte[] mac = rawData.Mac(password);
```

The default MAC algorithm is HMAC-SHA512.

**NOTE**: The `CryptoOptions.MacPassword` won't be used here, since you have 
to specify the MAC password in the method call already. The `MacPassword` is 
only used during encryption, if it is different from the encryption key.

### KDF (key stretching)

```cs
(byte[] stretchedPassword, byte[] salt) = password.Stretch(len: 64);
```

The default KDF algorithm is PBKDF#2, using 250,000 iterations.

**NOTE**: The used `Rfc2898DeriveBytes` uses SHA-1 as default hash algorithm, 
which isn't recommended anymore. Another hash algorithm can be chosen by 
setting `KdfPbKdf2Options`, which use SHA-384 per default. SHA-1 is still 
being used as fallback, if no options are given, to stay downward compatible. 
This fallback will be removed in a newer version of this library.

Example options usage:

```cs
(byte[] stretchedPassword, byte[] salt) = password.Stretch(len: 64, options: new KdfPbKdf2Options()
    {
        HashAlgorithm = HashSha3_384Algorithm.ALGORITHM_NAME
    });// KdfPbKdf2Options cast implicit to CryptoOptions
```

**NOTE**: In order to be able to use SHA3 hash algorithms, you'll need to 
reference the `wan24-Crypto-BC` NuGet package!

### Encryption

```cs
byte[] cipher = raw.Encrypt(password);
byte[] raw = cipher.Decrypt(password);
```

There are extension methods for memory and streams.

The default algorithms used:

| Usage | Algorithm |
| --- | --- |
| Symmetric encryption | AES-256-CBC (HMAC secured and Brotli compressed) |
| HMAC | HMAC-SHA512 |
| KDF | PBKDF#2 |
| Asymmetric key exchange and digital signature | Diffie Hellman secp521r1 |

**NOTE**: The `CryptoOptions.MacPassword` will optionally be used, if an 
additional MAC is being computed, but it doesn't affect the AEAD included MAC, 
which is going to be calculated separately. If no `MacPassword` was set, the 
final encryption password is going to be used instead.

#### Using asymmetric keys for encryption

This way you encrypt using a stored private key (which will be required for 
decryption later):

```cs
using IAsymmetricPrivateKey privateKey = AsymmetricHelper.CreateKeyExchangeKeyPair();
byte[] cipher = raw.Encrypt(privateKey);
byte[] raw = cipher.Decrypt(privateKey);
```

In case you want to encrypt for a peer using the peers asymmetric public key 
for performing a PFS key exchange:

```cs
// Peer creates a key pair (PFS or stored) and sends peerPublicKeyData to the provider
using IAsymmetricPrivateKey peerPrivateKey = AsymmetricHelper.CreateKeyExchangeKeyPair();
byte[] peerPublicKeyData = (byte[])peerPrivateKey.PublicKey;// Needs to be available at the provider

// Encryption at the provider (pfsKey shouldn't be stored and can be a new key for every cipher message)
using IAsymmetricPublicKey peerPublicKey = AsymmetricKeyBase.Import<IAsymmetricPublicKey>(peerPublicKeyData);// Deserialize the peers public key of any format
CryptoOptions options = EncryptionHelper.GetDefaultOptions();// Add the asymmetric key information for key pair creation
options.AsymmetricAlgorithm = peerPublicKey.Algorithm.Name;
options.AsymmetricKeyBits = peerPublicKey.Bits;
options.PublicKey = peerPublicKey;// Required for encrypting especially for the one specific peer
byte[] cipher;
using(IKeyExchangePrivateKey pfsKey = AsymmetricHelper.CreateKeyExchangeKeyPair(options))
    cipher = raw.Encrypt(pfsKey, options);// Only the peer can decrypt the cipher after pfsKey was disposed

// Decryption at the peer
byte[] raw = cipher.Decrypt(peerPrivateKey, options);
```

#### Time critical decryption

It's possible to define a maximum age for cipher data, which can't be 
decrypted after expired:

```cs
// Encryption
CryptoOptions options = new()
{
    TimeIncluded = true
};
byte[] cipher = raw.Encrypt(password, options);

// Decryption (required to be decrypted within 10 seconds, or the decryption will fail)
options = new()
{
    RequireTime = true,
    MaximumAge = TimeSpan.FromSeconds(10)
}
byte[] raw = cipher.Decrypt(password, options);
```

By defining `CryptoOptions.MaximumTimeOffset` you may define a time tolerance 
which is being used to be tolerant with peers having a slightly different 
system time.

### Asymmetric keys

#### Key exchange

PFS example:

```cs
// A: Create a key pair
using IKeyExchangePrivateKey privateKeyA = AsymmetricHelper.CreateKeyExchangeKeyPair();
byte[] publicKeyData = (byte[])privateKeyA.PublicKey;// Needs to be available at B

// B: Create a key pair, key exchange data and derive the shared key
using IAsymmetricPublicKey publicKeyA = AsymmetricKeyBase.Import<IAsymmetricPublicKey>(publicKeyData);// Deserialize the peers public key of any format
using IKeyExchangePrivateKey privateKeyB = AsymmetricHelper.CreateKeyExchangeKeyPair(new()
{
    AsymmetricAlgorithm = publicKeyA.Algorithm.Name,
    AsymmetricKeyBits = publicKeyA.Bits
});
(byte[] keyB, byte[] keyExchangeData) = privateKeyB.GetKeyExchangeData(publicKey);// Needs to be available at A

// A: Derive the exchanged key
byte[] keyA = privateKeyA.DeriveKey(keyExchangeData);

Assert.IsTrue(keyA.SequenceEquals(keyB));
```

The default key exchange algorithm is ECDH from a secp521r1 elliptic curve.

#### Digital signature

```cs
// Create a key pair for signature
using ISignaturePrivateKey privateKey = AsymmetricHelper.CreateSignatureKeyPair();

// Sign data
SignatureContainer signature = privateKey.SignData(anyData);

// Validate a signature
privateKey.PublicKey.ValidateSignature(signature, anyData);
```

The default signature algorithm is DSA from a secp521r1 elliptic curve.

## Too many options?

The `CryptoOptions` contains a huge collection of properties, which follow a 
simple pattern in case of en-/decryption: Which information should be included 
in the cipher header, and is an information in the header required? Because 
the options include information for all sections, there are single values 
which belongs to the specific section only. If you separate the options into 
sections, it's easy to overview:

| Section | Property | Description | Default value |
| --- | --- | --- | --- |
| Encryption | `Algorithm` | Encryption algorithm name | `null` (`AES256CBC`) |
|  | `FlagsIncluded` | Are the flags included in the header? | `true` |
|  | `RequireFlags` | Are the flags required to be included in the header? | `true` |
|  | `PrivateKeysStore` | Private keys store to use for decryption, using automatic key suite revision selection (the default can be set to `DefaultPrivateKeysStore`) | `null` |
|  | `PrivateKeyRevision` | Revision of the used private key suite (may be set automatic) | `0` |
|  | `PrivateKeyRevisionIncluded` | Is the private key suite revision included in the header? | `true`, if a `DefaultPrivateKeysStore` was set |
|  | `RequirePrivateKeyRevision` | Is the private key suite revision required to be included in the header? | `true`, if a `DefaultPrivateKeysStore` was set |
|  | `RngSeeding` | RNG seeding options (overrides `RND.AutoRngSeeding`) | `null` |
| MAC | `MacAlgorithm` | MAC algorithm name | `null` (`HMAC-SHA512`) |
|  | `MacIncluded` | Include a MAC in the header | `true` |
|  | `RequireMac` | Is the MAC required in the header? | `true` |
|  | `CounterMacAlgorithm` | Counter MAC algorithm name | `null` |
|  | `CounterMacIncluded` | Include a counter MAC in the header | `false` |
|  | `RequireCounterMac` | Is the counter MAC required in the header? | `false` |
|  | `ForceMacCoverWhole` | Force the MAC to cover all data | `false` |
|  | `RequireMacCoverWhole` | Is the MAC required to cover all data? | `false` |
|  | `MacPassword` | Password to use for a MAC | `null` |
| Encryption / Key creation / Signature | `AsymmetricAlgorithm` | Asymmetric algorithm name | `null` (`ECDH` for encryption, `ECDSA` for signature) |
|  | `AsymmetricCounterAlgorithm` | Asymmetric counter algorithm name | `null` |
|  | `KeyExchangeData` | Key exchange data (includes counter key exchange data; generated automatic) | `null` |
|  | `RequireKeyExchangeData` | Is the key exchange data required in the header? | `false` |
|  | `PrivateKey` | Private key for key exchange | `null` |
|  | `CounterPrivateKey` | Private key for counter key exchange (required when using a counter asymmetric algorithm) | `null` |
|  | `PublicKey` | Public key for key exchange (if not using a PFS key) | `null` |
|  | `CounterPublicKey` | Public key for counter key exchange (required when using a counter asymmetric algorithm and not using a PFS key) | `null` |
| KDF | `KdfAlgorithm` | KDF algorithm name | `null` (`PBKDF2`) |
|  | `KdfIterations` | KDF iteration count | `1` |
|  | `KdfOptions` | String serialized KDF algorithm options | `null` |
|  | `KdfSalt` | KDF salt (generated automatic) | `null` |
|  | `KdfAlgorithmIncluded` | Include the KDF information in the header | `true` |
|  | `RequireKdfAlgorithm` | Is the KDF information required in the header? | `true` |
|  | `CounterKdfAlgorithm` | Counter KDF algorithm name | `null` |
|  | `CounterKdfIterations` | Counter KDF iteration count | `1` |
|  | `CounterKdfOptions` | String serialized KDF algorithm options | `null` |
|  | `CounterKdfSalt` | Counter KDF salt (generated automatic) | `null` |
|  | `CounterKdfAlgorithmIncluded` | Include the counter KDF information in the header | `false` |
|  | `RequireCounterKdfAlgorithm` | Is the counter KDF information required in the header? | `false` |
| Payload | `PayloadData` | Plain payload | `null` |
|  | `PayloadIncluded` | Is the payload object data included in the header? | `false` |
|  | `RequirePayload` | Is payload object data required in the header? | `false` |
| Serializer version | `CustomSerializerVersion` | Serializer version number (set automatic) | `null` |
|  | `SerializerVersionIncluded` | Include the serializer version number in the header | `true` |
|  | `RequireSerializerVersion` | Is the serializer version number required in the header? | `true` |
| Header version | `HeaderVersion` | Header version number (set automatic) | `1` |
|  | `HeaderVersionIncluded` | Is the header version included in the header? | `true` |
|  | `RequireHeaderVersion` | Is the header version required in the header? | `true` |
| Encryption time | `Time` | Encryption timestamp (UTC) | `null` |
|  | `TimeIncluded` | Is the encryption time included in the header? | `false` |
|  | `RequireTime` | Is the encryption time required to be included in the header? | `false` |
|  | `MaximumAge` | Maximum age of cipher data (the default can be set to `DefaultMaximumAge`) | `null` |
|  | `MaximumTimeOffset` | Maximum time offset for a peer with a different system time (the default can be set to `DefaultMaximumTimeOffset`) | `null` |
| Compression | `Compressed` | Should the raw data be compressed before encryption? | `true` |
|  | `Compression` | The `CompressionOptions` instance to use (will be set automatic, if not given) | `null` |
|  | `MaxUncompressedDataLength` | Maximum uncompressed data length in bytes (when decrypting) | `-1` |
| Hashing / Signature | `HashAlgorithm` | The name of the hash algorithm to use | `null` (`SHA512`) |
| Key creation | `AsymmetricKeyBits` | Key size in bits to use for creating a new asymmetric key pair | `1` |
| Stream options | `LeaveOpen` | Leave the processing stream open after operation? | `false` |
| Debug options | `Tracer` | Collects tracing information during en-/decryption | `null` |

Other options, which are not listed here, are used internal only.

If you use a new instance of `CryptoOptions`, all defaults will be applied. 
You can override these defaults in the static `*Helper.Default*` properties, 
or by setting other values in the `CryptoOptions` instance, which you use when 
calling any method.

For encryption these sections matter:

- Encryption
- MAC
- PFS
- KDF
- Payload
- Serializer version
- Header version
- Encryption time
- Compression
- Stream options

In case you want to use the `*Counter*` options, you'll need to set the 
`CounterPrivateKey` value.

For MAC these sections matter:

- MAC
- Stream options

For hashing these sections matter:

- Hashing
- Stream options

For asymmetric key creation the "Key creation" section matters.

For signature these sections matter:

- Signature
- Hashing
- Stream options

The `CryptoEnvironment` helps configuring the whole `wan24-Crypto` environment 
at once by providing an options class which contains all the options that one 
might miss, when not knowing where to look at:

```cs
CryptoEnvironment.Configure(new()
{
    ...
});
```

**NOTE**: See the developer reference for details of the 
`CryptoEnvironment.Options` class. Options will only be applied, if they have 
a non-null value.

The `CryptoEnvironment` has also some static properties for storing some 
singleton instances (which are used as default for the configurable options).

## Crypto suite

You can use a `CryptoOptions` instance as crypto suite. The type can be binary 
serialized (using the `Stream-Serializer-Extensions`) for storing/restoring 
to/from anywhere.

**NOTE**: Only crypto suite relevant information will be serialized! This 
excludes:

- `SerializerVersion`
- `HeaderVersion`
- `PrivateKeystore` (needs to be stored in another place; a default can be set 
in `DefaultPrivateKeysStore`)
- `PrivateKeyRevision` (will be managed automatic)
- `PrivateKey` (needs to be stored in another place)
- `CounterPrivateKey` (needs to be stored in another place)
- `PublicKey`
- `CounterPublicKey`
- `KeyExchangeData`
- `PayloadData`
- `Time`
- `LeaveOpen`
- `MacPosition`
- `Mac`
- `HeaderProcessed`
- `Password`
- `MacPassword`
- `Tracer`

## PKI

Using the `AsymmetricSignedPublicKey` type, you can implement a simple PKI, 
which allows to

- define trusted root keys
- define a key revocation list
- sign public keys
- validate signed public keys until the root signer key

```cs
// Create the root key pair
using ISignaturePrivateKey privateRootKey = AsymmetricHelper.CreateSignatureKeyPair();

// Self-sign the public root key
using AsymmetricSignedPublicKey signedPublicRootKey = new(privateRootKey.PublicKey);
signedPublicRootKey.Sign(privateRootKey);

// Create a key pair, which will be signed, and a signing request
using ISignaturePrivateKey privateKey = AsymmetricHelper.CreateSignatureKeyPair();
using AsymmetricPublicKeySigningRequest signingRequest = new(privateKey.PublicKey);

// Sign the public key
using AsymmetricSignedPublicKey signedPublicKey = signingRequest.GetAsUnsignedKey();
signedPublicKey.Sign(privateRootKey);

// Setup the PKI (minimal setup for signed public key validation)
AsymmetricSignedPublicKey.RootTrust = 
    // Normally you would have a DBMS which stores the trusted public key IDs
    (id) => id.SequenceEqual(privateRootKey.ID);
AsymmetricSignedPublicKey.SignedPublicKeyStore = (id) => 
{
    // Normally you would have a DBMS which stores the known keys
    if(id.SequenceEqual(privateRootKey.ID)) return signedPublicRootKey;
    if(id.SequenceEqual(privateKey.ID)) return signedPublicKey;
    return null;
};
// Normally you would have a DBMS which stores a revocation list for AsymmetricSignedPublicKey.SignedPublicKeyRevocation

// Validate the signed public key
signedPublicKey.Validate();
```

As you can see, it's a really simple PKI implementation. It's good for 
internal use, and if there won't be too many keys to manage. For managing a 
larger amount of keys, you can use the `SignedPkiStore`:

```cs
using SignedPkiStore pki = new();
pki.AddTrustedRoot(signedPublicRootKey);
pki.AddGrantedKey(signedPublicKey);
pki.EnableLocalPki();
```

By calling `EnableLocalPki` all PKI callbacks in `AsymmetricSignedPublicKey` 
will be set with methods from the `SignedPkiStore` instance. This allows 
signed key and signature validations using your PKI.

The `GetKey` methods will find the hosted key with the given ID of the public 
key. The PKI may also host revoked keys. By revoking a key, it'll be removed 
from the trusted root/granted key tables, and `GetKey` will throw on key 
request.

### Signed attributes and other PKI extensions

The signed attributes are fully customizable and not pre-defined at all, 
you're the designer of your own PKI implementation. In order you want some 
inspiration and ideas, you may have a look at the `SignedAttributes` class, 
wich contains some examples/suggestions for signed attributes and their names.

| Name | Usage |
| ---- | ----- |
| Domain | PKI domain name to identify/validate the keys PKI |
| OwnerId | Foreign owner ID for loading meta data from a store (should be encrypted by the PKI host) |
| KeyValidationUri | URI that should point to a RESTful API for online key revokation validation |
| GrantedKeyUsages | Allowed usages for the signed key |
| KePublicKey | Identifier of the public key for the key exchange with the owner |
| KePublicCounterKey | Identifier of the public counter key for the key exchange with the owner |
| SigPublicKey | Identifier of the public signature key of the owner |
| SigPublicCounterKey | Identifier of the public signature counter key of the owner |
| CipherSuite | Serialized `CryptoOptions` to use with the signed key owner |
| Serial | Serial number (the key revision of the owner context) |

Some key meta data like the creation and expiration time, or a nonce, is 
included in a lower level in the `AsymmetricSignedPublicKey` already, and 
don't need to appear in the signed attribute list again.

A key signing request may algo contain more attributes than the final signed 
key, if you want to give signing instructions to the PKI, for example. The PKI 
may remove/replace those instructions, for example.

As said before, the list above doesn't need to be implemented fully, and it 
may be extended with any attribute that your PKI requires in addition. There 
are only suggestions for value formats - but how you implement it finally, is 
your business only. If you implement the suggested attributes and value 
formats, you'll have a fully usable PKI. In addition a key revokation list 
would be a nice feature (as a part of a RESTful PKI API). For a trusted root 
key list you could use the `PublicKeySuiteStore`, for example. A key 
revokation list may only contain the IDs of revoked keys, which are not yet 
expired.

You can use the `AsymmetricKeySigner` as template for a key signing request 
handler, which supports the attributes from above. You should implement 
algorithm validation etc. for a key signing request by yourself, since such 
requirements are not really good to match with a basic API.

## PAKE

`Pake` (see tests) can be used for implementing a password authenticated key 
exchange, which should be wrapped with a PFS protocol in addition. PAKE uses 
symmetric cryptographic algorithms only and uses random bytes for session key 
generation. After signup, it can be seen as a symmetric PFS protocol, if the 
random bytes are random for each session and never stored as communicated 
between the peers.

**CAUTION**: PAKE doesn't support counter algorithms! For working with PQ 
counter algorithms, you'll have to combine two PAKE with different options by 
yourself.

**NOTE**: For PAKE both peers need to use the same KDF and MAC options. If the 
algorithm is going to be changed, a new signup has to be performed. In case a 
peer changes its authentication (identifier or key), a new signup operation 
has to be performed, too. A signup should always be performed using an 
additional factor, which was communicated using another transport. An 
authentication may use a second factor, while it's recommended to use at last 
two factors for each operation.

PAKE allows single directional authenticated messages and should be performed 
bi-directional for a bi-directional communication, if possible.

While a MAC can be computed fast, KDF needs time. During a PAKE handshake both 
algorithms are used on both peers. But the server will perform KDF only after 
a MAC was validated, which closes a door for DoS attacks by an anonymous 
attacker.

**NOTE**: Default options for PAKE can be overridden by setting a custom value 
to `Pake.DefaultOptions`.

`FastPakeClient/Server` allow fast followup authentications after the first 
authentication of an already known peer (after a signup was performed). 
They're designed to be alive for a longer time, if the server expects a client 
to perform multiple authentications. They're good for a single-directional UDP 
protocol, for example, where each message is PAKE authenticated, and each 
followup message is encrypted using the session key of the first 
authentication message.

**NOTE**: This PAKE implementation is patent free!

## Client/server authentication protocol

### Asymmetric keys + PAKE

`wan24-Crypto` implements a client/server authentication protocol for stream 
connections (like a TCP `NetworkStream`). This protocol allows

- server public key request
- signup
- authentication

while all features are optional. It implements Zero Knowledge Password Proof 
(ZKPP) and Perfect Forward Secrecy (PFS).

During a signup an asymmetric public key of the client can be signed by the 
server for long term use.

The authentication is encrypted using

- (hopefully pre-shared) server public keys and PFS keys
- PAKE

If the public servers keys are not pre-shared, a PKI should be used to ensure 
working with valid keys.

See the tests (`Auth_Tests.cs`) for an example of a simple but working client/
server implementation.

On signup, the server needs to store the PAKE identity and the clients public 
keys, which then need to be provided for a later authentication process. The 
`ClientAuthContext` has all the information required to handle a signup or an 
authentication, and it contains the exchanged PFS session key for encrypted 
communication, too.

For optimal security (in 2023), you should use an asymmetric PQC algorithm for 
the key exchange and signature key, and a common non-PQC algorithm as counter 
key exchange and signature key. You can find asymmetric PQC algorithms in the 
`wan24-Crypto-BC` library, for example.

**NOTE**: Login username and password won't be communicated to the server. If 
any authentication related information changes, a follow-up signup needs to be 
performed.

The signup process (as seen from the client; is bi-directional always):

- Send the clients public PFS key
- Start encryption using the servers public key and a private PFS key of the 
client
- Send the clients public counter PFS key
- Extend the encryption using the servers public counter key and a private PFS 
key of the client
- Send the PAKE signup request and extend the encryption using the PAKE 
session key (the request contains the public key suite and a key signing 
request, if this is the signup of a new user, or the public key suite changed)
- Sign the authentication sequence using the private client key
- Validate the server signature of the authentication sequence
- Receive the servers public PFS key
- Extend the encryption using the private key and the servers public PFS key
- Receive the servers public counter PFS key
- Extend the encryption with the PFS key computed using the private PFS keys 
and the servers public PFS keys
- Get the signed public client key
- Sign the public key suite including the signed public key and store the 
private and public key suites

**NOTE**: The PAKE authentication allows to attach any payload, which enables 
the app to extend the process with additional meta data as required.

A later authentication process (as seen from the client; may be uni-
directional):

- Send the clients public PFS key
- Start encryption using the servers public key and a private PFS key of the 
client
- Send the clients public counter PFS key
- Extend the encryption using the servers public counter key and a private PFS 
key of the client
- Send the PAKE authentication request and extend the encryption using the 
PAKE session key
- Sign the authentication sequence using the private client key

For a bi-directional communication channel in addition:

- Validate the server signature of the authentication sequence
- Receive the servers public PFS key
- Extend the encryption using the private key and the servers public PFS key
- Receive the servers public counter PFS key
- Extend the encryption using the PFS key computed using the private PFS keys 
and the servers public PFS keys

**WARNING**: An uni-directional connection does use a PFS key, but this key is 
being applied on a pre-shared long term key only.

**NOTE**: Since a temporary client like a browser may not be able to store the 
private client keys, such a client may only use the signup and not send a key 
signing request. Then the server is required to identify the authenticating 
client using the PAKE identifier (not the public key ID).

In total at last three session keys are being exchanged during a request (six 
session keys for bi-directional communication). The first two keys are pseudo-
PFS keys, while the third key is the PAKE session key. Each part of the 
authentication sequence will be encrypted using the latest exchanged session 
key (encryption does change each time a new session key can be derived at the 
server).

**NOTE**: The encryption key will always be _extended_ by the next derived 
key, but _not replaced_.

To avoid replay-attacks, the server should implement methods to deny re-using 
PFS keys or random byte sequences. A timestamp validation is implemented 
already (which defaults to a maximum time offset of 5 minutes to the clients 
system time). So the server should ensure, that a (pseudo-)PFS key or random 
byte sequence can't be re-used within five minutes after it was received from 
a client.

**NOTE**: The long term client key exchange keys can be used for encrypting an 
off-session peer-to-peer message. They're not used for signup/authentication.

Things that must be known in advance are the used algorithms, while the PFS 
keys use the public server keys algorithms and key sizes. But these algorithms 
must be pre-defined in both (client and server) apps anyway:

- Hash algorithm
- MAC algorithm
- KDF algorithm
- Encryption algorithm (and other `CryptoOptions` settings for encryption)

**CAUTION**: The chosen encryption algorithm must not require MAC 
authentication (while built-in MAC authentication like with AEAD is ok). You 
can find a stream cipher in the `wan24-Crypto-BC` library, for example. The 
encryption settings shouldn't use KDF to avoid too much overhead (KDF will be 
used for PAKE already).

### PAKE authentication only

Quiet different from the "Asymmetric keys + PAKE" authentication protocol, 
there is another implementation, which uses PAKE only. See the tests 
(`PakeAuth_Tests.cs`) for an example of a simple but working client/server 
implementation.

This protocol allows

- signup
- authentication

while all features are optional. It implements Zero Knowledge Password Proof 
(ZKPP) and Perfect Forward Secrecy (PFS).

**CAUTION**: At last the signup communication is required to be wrapped with 
a PFS protocol! Use a TLS socket, for example. A later authentication _may_ be 
performed using a raw socket.

During the signup the server will respond a random signup to the client. The 
produces PAKE values need to be stored on both peers for later authentication.

**WARNING**: This authentication protocol doesn't support the use of a pre-
shared key for the signup. This clearly opens doors for a MiM attack during 
the signup: If the signup communication was compromised, the attacker will be 
able to authenticate successful later! It's absolutely required to use a 
wrapping PFS protocol which ensures the server identity, before sending any 
signup information.

For authentication, the client sends the identifier of the servers PAKE 
values, which have been pre-shared during the signup. Using random bytes a 
temporary session key will be calculated and used to send the PAKE 
authentication request. The temporary session key will then be extended using 
the now fully exchanged PAKE session key.

**NOTE**: The authentication _may_ use a raw socket, while a wrapping PFS 
protocol is of course never a mistake. However, if using raw sockets, a MiM is 
able to know who is authenticating, because the servers random PAKE identifier 
needs to be sent plain (and this value won't change, if not forced).

Things that must be known in advance are the used algorithms, which must be 
pre-defined in both (client and server) apps:

- MAC algorithm
- KDF algorithm
- Encryption algorithm (and other `CryptoOptions` settings for encryption)

**CAUTION**: The chosen encryption algorithm must not require MAC 
authentication (while built-in MAC authentication like with AEAD is ok). You 
can find a stream cipher in the `wan24-Crypto-BC` library, for example. The 
encryption settings shouldn't use KDF to avoid too much overhead (KDF will be 
used for PAKE already).

In total this authentication may be a good choice for use with fixed client 
devices, which are able to store the servers PAKE values in a safe way for the 
long term. But also temporary devices may benefit, if they'll connect to a 
server multiple times.

## Random number generator

You can use `RND` as a random data source. `RND` is customizable and falls 
back to `RandomNumberGenerator` from .NET. It uses `/dev/random` as data 
source, if available.

```cs
byte[] randomData = RND.GetBytes(123);
```

**NOTE**: `/dev/random` may be too slow for your requirements. If you don't 
want to use `RandomDataGenerator` (which can speed up `RND` a lot), you can 
disable `/dev/random`:

```cs
RND.UseDevRandom = false;
```

**NOTE**: In case you want to force using `/dev/random` _ONLY_:

```cs
RND.RequireDevRandom = true;// This will cause RND to throw on Windows!
```

The `RandomDataGenerator` is an `IHostedService` which can be customized, but 
falls back to `RND` per default. The service uses a buffer to pre-buffer 
random data, in case your RNG is slow. It's possible to define custom 
fallbacks which are being used in case the buffer doesn't have enough data to 
satisfy a request. If you use a `RandomDataGenerator`, you can set the 
instance to `RND.Generator` to use it per default.

The full generator process is:

1. Try reading pre-buffered random data
2. If not satisfied, call the defined fallback RNG delegates (`RND` methods 
are preset)
3. Default `RND` methods use `RandomNumberGenerator`, finally

Each step in this process can be customized in `RND` AND 
`RandomDataGenerator`, while the defaults of `RandomDataGenerator` fall back 
to `RandomStream` and `RND`, and the methods of `RND` use `RND.Generator` or 
fall back to `RandomNumberGenerator`. To simplify that and avoid an endless 
recursion in your code: **DO NOT** call `RND.Get/FillBytes(Async)` from a 
customized `RandomDataGenerator`! **DO** call `RND.DefaultRng(Async)` instead.

If you use the plain `RandomDataGenerator`, it uses the `RandomStream` as 
random data source, if `/dev/random` isn't available or disabled. 
(`RandomStream` uses `RandomNumberGenerator`, finally.)

There's another `Rng` type, which is a `RandomNumberGenerator` implementation 
that skips the OS random number generator implementation and uses `RND` 
instead (also the static methods of `RandomNumberGenerator` are overridden). 
The `RngHelper` extends any `RandomNumberGenerator` instance with a `GetInt32` 
method (which applies to customized `Rng` instances, too, since they extend 
`RandomNumberGenerator`).

**NOTE**: `Rng` implements non-zero random number generation. However, any non-
zero random byte sequence isn't as random as it could be anymore - keep that 
in mind.

To sum it up: Use `RND` for (optional customized) getting cyptographic random 
bytes. You can use `SecureRandomStream.Instance`, too (it uses `RND` on 
request). Use `Rng` as (also asynchronous) random integer generator, or where 
a `RandomNumberGenerator` instance is required.

**CAUTION**: True randomness is the most important source of security for any 
crypto application. PRNG and CSRNG random sources, and even physical phenomen 
based hardware random sources won't produce _true_ random, and/or can be 
manipulated in some way to produce predictable random data, unless it's a QRNG 
source.

### Seeding

Use the `RND.AddSeed(Async)` methods for seeding your RNG. The 
`AddDevRandomSeed(Async)` only seed `/dev/random`, while when calling 
`AddSeed(Async)`, the method will try to seed

1. the `RND.SeedConsumer`
2. the `RND.Generator`
3. `/dev/random`

and return after providing the seed to the first available target, or when 
there's no target for consuming the seed.

**CAUTION**: Be aware of the patent US10402172B1!

### Seeding automatic

A seedable RNG (`ISeedableRng`) can be seeded automatic using

- received IV bytes
- received cipher data
- received random bytes

**CAUTION**: Even if it's extremely unlikely, an untrusted seed source _may_ 
be able to cause a RNG to produce predictable random data, unless it combines 
QRNG entropy.

To enable automatic seeding, set the seed source flags to `RND.AutoRngSeeding`.

Per default the `RND.Generator` will be seeded, unless you specify another 
seed target in `RND.SeedConsumer`. A seed consumer needs to implement the 
`ISeedableRng` interface, which `RandomDataGenerator` does, for example.

Seeding during encryption can be overridden using `CryptoOptions.RngSeeding`.

Seeding during PAKE authentication can be overridden using the given options 
for encryption.

When deserializing the `SignatureContainer` embedded signed data, the nonce 
will be seeded, if `RND.AutoRngSeeding` has the `Random` flag.

Because seeding may be synchronized, there's a `RngSeederQueue` queue worker, 
which is a simple hosted service that seeds the given target `ISeedableRng` in 
background, using a copy of the given seeds. The `RngSeederQueue` may be 
customized easily by extending the type (pregnant methods are virtual).

**CAUTION**: Be aware of the patent US10402172B1!

### Some words on secure seeding

A PRNG isn't enough, and even a CSRNG isn't enough, if the RNG's seed is not 
good. Modern OS CSRNG implementations use hardware and software environment 
information like

- system clock
- IP stack I/O timings
- temperature sensors values
- environment sounds
- harddisc values
- user information digest
- process ID
- thread ID
- ...and so on.

But this still isn't really good, because all sources can be manipulated 
and/or predicted. The only really good seed source is a quantum device which 
is used by a QRNG. But not everyone has access to a QRNG, and the hardware is 
expensive, too.

A company may decide to buy a QRNG hardware, which is a good investment in 
2023, since quantum computing resources are becoming available to anyone now, 
and the development speed is really amazing (and will speed up more with the 
also fast growing AI possibilities!).

But a private person might run into problems, unless there's a free QRNG seed 
source available online, hopefully for free. It'll take some time until 
enduser systems will contain a chip which can produce QRNG sequences on the 
local mashine, and isn't too expensive, so everyone can afford to own one.

Anyway, when using a CSRNG, finally, it should be re-seeded as often as 
possible, because if a CSRNG output is being collected over a time, and the 
underlaying algorithm is known, the future output becomes predictable - and 
this is something you'd like to avoid as good as possible. There are several 
steps that you should implement fully, if possible in any way:

1. Use a PRNG and seed it with CSRNG data from the operating system
2. Wrap the PRNG with a CSRNG which uses an underlaying stream cipher to 
encrypt the PRNG's random data stream
3. Re-seed the PRNG as often as possible using at last CSRNG data from the 
operating system, and if possible in combination with entropy from a QRNG

Of course the best solution would be to use a QRNG instead of a PRNG in step 
1, because then you wouldn't need to re-seed usually. But step 2 is important 
in all cases, please don't miss it! A good practice is to combine multiple 
entropy sources, at last for seeding, but also for the RNG's output, which 
you're going to use for symmetric keys (DEK), for example.

If you carefully red and understood this information, you should get quiet 
good results with a CSRNG already, even you don't have access to a quantum 
entropy source. The `wan24-Crypto` and `wan24-Crypto-BC` libraries should 
offer everything a C# developer needs for a better random number source.

**NOTE**: Even the best PQC algorithm will _fail_ when not using a good RNG!

## Object encryption

By using the `DekAttribute` and `EncryptAttribute` (and optional the 
`IEncryptProperties` interface) you can en-/decrypt objects with the 
`ObjectEncryption` helper methods/extensions:

```cs
public class YourType : IEncryptProperties
{
    [Dek]
    public byte[] Dek { get; set; } = null!;

    [Encrypt]
    public byte[] Raw { get; set; } = null!;
}
```

**NOTE**: `null` values won't be en-/decrypted! Using the 
`IEncryptPropertiesExt` interface your object can define en-/decryption 
handler methods.

The `Dek` will hold a random data encryption key, while all properties having 
the `Encrypt` attribute will be encrypted using that DEK:

```cs
YourType obj = new()
{
    Raw = ...
};
obj.EncryptObject(kek);
```

**NOTE**: The real object type will be used for finding properties to process, 
not the generic method argument of `EncryptObject` and `DecryptObject`.

The `kek` holds the key, which is used for the DEK encryption. Use 
`DecryptObject` for decryption.

The `DekAttribute` and `EncryptAttribute` can be extended to override the 
methods that are used to get/set values.

The rules for the used keys are simple:

1. If you have a `Dek` property, it'll be used to store a KEK encrypted random 
DEK (which will be (re-)generated for each encryption)
2. If you don't have a `Dek` property, you'll need to specify the DEK in the 
method parameters (and of course no KEK parameter value is required)

## Notes

Sometimes you'll read something like "will be disposed" or "will be cleared" 
in the documentation. These are important diclaimers, which should be 
respected in order to work safe with sensitive data.

**WARNING**: The disclaimer may be missing in some places!

### Will be disposed

When noted to a given value, it'll be disposed after the desired operation, or 
when the hosting object is being disposed.

When noted to a returned value, and you don't want to use the value only for a 
short term (during the hosted value wasn't disposed for sure), you should 
consider to create a copy. The hosting object will dispose the value, when 
it's being disposed.

### Should be disposed

This is a disclaimer that reminds you to dispose a returned value after use.

### Will be cleared

When noted to a given value, it'll be cleared after the desired operation, or 
when the hosting object is being disposed/cleared.

When noted to a returned value, and you don't want to use the value only for a 
short term (during the hosted value wasn't disposed/cleared for sure), you 
should consider to create a copy. The hosting object will clear the value, 
when it's being disposed/cleared.

### Should be cleared

This is a disclaimer that reminds you to clear a returned value after use. For 
this usually you can use the `Clear` or `Clean` (extension?) method of the 
value. (In case of `Memory<T>` or `Span<T>` it's `Clean`, because `Clear` is 
used to zero out the value already, while `Clean` will fill it with random 
bytes before.)

## Algorithm IDs

Internal each algorithm has an unique ID within a category:

- Asymmetric cryptography
- Symmetric cryptography
- Hashing
- MAC
- KDF

If you'd like to implement inofficial algorithms on your own, please use the 
ID bits 24-32 only to avoid possible collisions with official libraries! These 
are the official implementation IDs (not guaranteed to be complete):

| Algorithm | ID | Library |
| --- | --- | --- |
| **Asymmetric cryptography** |  |  |
| ECDH | 0 | wan24-Crypto |
| ECDSA | 1 | wan24-Crypto |
| CRYSTALS-Kyber | 2 | wan24-Crypto-BC |
| CRYSTALS-Dilithium | 3 | wan24-Crypto-BC |
| FALCON | 4 | wan24-Crypto-BC |
| SPHINCS+ | 5 | wan24-Crypto-BC |
| FrodoKEM | 6 | wan24-Crypto-BC |
| NTRUEncrypt | 7 | wan24-Crypto-BC |
| **Symmetric cryptography** |  |  |
| AES-256-CBC | 0 | wan24-Crypto |
| ChaCha20 | 1 | wan24-Crypto-BC |
| XSalsa20 | 2 | wan24-Crypto-BC |
| AES-256-GCM | 3 | wan24-Crypto-BC |
| XCrypt | 4 | (none) |
| Serpent 256 CBC | 5 | wan24-Crypto-BC |
| Serpent 256 GCM | 6 | wan24-Crypto-BC |
| Twofish 256 CBC | 7 | wan24-Crypto-BC |
| Twofish 256 GCM | 8 | wan24-Crypto-BC |
| **Hashing** |  |  |
| MD5 | 0 | wan24-Crypto |
| SHA-1 | 1 | wan24-Crypto |
| SHA-256 | 2 | wan24-Crypto |
| SHA-384 | 3 | wan24-Crypto |
| SHA-512 | 4 | wan24-Crypto |
| SHA3-256 | 5 | wan24-Crypto-BC |
| SHA3-384 | 6 | wan24-Crypto-BC |
| SHA3-512 | 7 | wan24-Crypto-BC |
| **MAC** |  |  |
| HMAC-SHA-1 | 0 | wan24-Crypto |
| HMAC-SHA-256 | 1 | wan24-Crypto |
| HMAC-SHA-384 | 2 | wan24-Crypto |
| HMAC-SHA-512 | 3 | wan24-Crypto |
| HMAC-SHA3-256 | 4 | wan24-Crypto-BC |
| HMAC-SHA3-384 | 5 | wan24-Crypto-BC |
| HMAC-SHA3-512 | 6 | wan24-Crypto-BC |
| TPMHMAC-SHA-1 | 7 | wan24-Crypto-TPM |
| TPMHMAC-SHA-256 | 8 | wan24-Crypto-TPM |
| TPMHMAC-SHA-384 | 9 | wan24-Crypto-TPM |
| TPMHMAC-SHA-512 | 10 | wan24-Crypto-TPM |
| **KDF** |  |  |
| PBKDF#2 | 0 | wan24-Crypto |
| Argon2id | 1 | wan24-Crypto-NaCl |

PAKE has no algorithm ID, because it doesn't match into any category (there is 
no PAKE multi-algorithm support implemented).

## Counter algorithms

A counter algorithm is being applied after the main algorithm. So the main 
algorithm result is secured by the counter algorithm result. You can use this 
in case you want to double security, for example when using post quantum 
algorithms, which may not be trustable at present.

The `HybridAlgorithmHelper` allows to set default hybrid algorithms for

- key exchange in `KeyExchangeAlgorithm`
- signature in `SignatureAlgorithm`
- KDF in `KdfAlgorithm`
- MAC in `MacAlgorithm`

and exports some helper methods, which are being used internal during 
encryption (you don't need to use them unless you have to). If you want the 
additional hybrid algorithms to be used every time, you can set the

- `EncryptionHelper.UseHybridOptions`
- `AsymmetricHelper.UseHybridKeyExchangeOptions`
- `AsymmetricHelper.UseHybridSignatureOptions`

to `true` to extend used `CryptoOptions` instances by the algorithms defined 
in the `HybridAlgorithmHelper` properties.

**WARNING**: The `HybridAlgorithmHelper` counter MAC implementation isn't 
really good - it's only a trade-off to gain compatibility and performance. You 
should consinder to create a counter MAC from the whole raw data manually, if 
possible, instead.

### Post quantum safety

Some of the used cryptographic algorithms are quantum safe already, but 
especially the asymmetric algorithms are not post quantum safe at all. If you 
use an extension library which offers asymmetric post quantum safe algorithms 
for key exchange and signature, you can enforce post quantum safety for all 
used default algorithms by calling `CryptoHelper.ForcePostQuantumSafety`. This 
method will ensure that all used default algorithms are post quantum safe. In 
case it's not possible to use post quantum algorithms for all defaults, this 
method will throw an exception.

**NOTE**: AES-256 and SHA-384+ (and HMAC-SHA-384+) are considered to be post 
quantum-safe algorithms, while currently no post quantum-safe asymmetric 
algorithms are implemented in this main library (`wan24-Crypto-BC` does 
implement some), since .NET doesn't offer any API (this may change with 
coming .NET releases).

## Disclaimer

`wan24-Crypto` and provided sub-libraries are provided "as is", without any 
warranty of any kind. Please read the license for the full disclaimer.

This library uses the available .NET cryptographic algorithms and doesn't 
implement any "selfmade" cryptographic algorithms. Extension libraries may add 
other well known third party cryptographic algorithm libraries, like Bouncy 
Castle. Also "selfmade" cryptographic algorithms may be implemented by 
extensions.
