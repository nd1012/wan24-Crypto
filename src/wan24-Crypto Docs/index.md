# wan24-Crypto

This library exports a generic high level crypto API, which allows to use an 
implemented cryptographic algorithm to be applied using a simple interface.

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
| **KDF key stretching** | PBKDF#2 (20,000 iterations per default) |

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

### KDF (key stretching)

```cs
(byte[] stretchedPassword, byte[] salt) = password.Stretch(len: 64);
```

The default KDF algorithm is PBKDF#2, using 20,000 iterations.

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
| MAC | `MacAlgorithm` | MAC algorithm name | `null` (`HMAC-SHA512`) |
|  | `MacIncluded` | Include a MAC in the header | `true` |
|  | `RequireMac` | Is the MAC required in the header? | `true` |
|  | `CounterMacAlgorithm` | Counter MAC algorithm name | `null` |
|  | `CounterMacIncluded` | Include a counter MAC in the header | `false` |
|  | `RequireCounterMac` | Is the counter MAC required in the header? | `false` |
|  | `ForceMacCoverWhole` | Force the MAC to cover all data | `false` |
|  | `RequireMacCoverWhole` | Is the MAC required to cover all data? | `false` |
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
|  | `KdfSalt` | KDF salt (generated automatic) | `null` |
|  | `KdfAlgorithmIncluded` | Include the KDF information in the header | `true` |
|  | `RequireKdfAlgorithm` | Is the KDF information required in the header? | `true` |
|  | `CounterKdfAlgorithm` | Counter KDF algorithm name | `null` |
|  | `CounterKdfIterations` | Counter KDF iteration count | `1` |
|  | `CounterKdfSalt` | Counter KDF salt (generated automatic) | `null` |
|  | `CounterKdfAlgorithmIncluded` | Include the counter KDF information in the header | `false` |
|  | `RequireCounterKdfAlgorithm` | Is the counter KDF information required in the header? | `false` |
| Payload | `PayloadData` | Plain payload | `null` |
|  | `PayloadIncluded` | Is the payload object data included in the header? | `false` |
|  | `RequirePayload` | Is payload object data required in the header? | `false` |
| Serializer version | `SerializerVersion` | Serializer version number (set automatic) | `null` |
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
| Hashing / Signature | `HashAlgorithm` | The name of the hash algorithm to use | `null` (`SHA512`) |
| Key creation | `AsymmetricKeyBits` | Key size in bits to use for creating a new asymmetric key pair | `1` |
| Stream options | `LeaveOpen` | Leave the processing stream open after operation? | `false` |

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

## Crypto suite

You can use a `CryptoOptions` instance as crypto suite. The type can be binary 
serialized (using the `Stream-Serializer-Extensions`) for storing/restoring 
to/from anywhere.

**NOTE**: Only crypto suite relevant information will be serialized! This 
excludes:

- `SerializerVersion`
- `HeaderVersion`
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
internal use, and if there won't be too many keys to manage.

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
| **Symmetric cryptography** |  |  |
| AES256CBC | 0 | wan24-Crypto |
| CHACHA20 | 1 | wan24-Crypto-BC |
| XSALSA20 | 2 | wan24-Crypto-BC |
| AES256CM | 3 | wan24-Crypto-BC |
| **Hashing** |  |  |
| MD5 | 0 | wan24-Crypto |
| SHA1 | 1 | wan24-Crypto |
| SHA256 | 2 | wan24-Crypto |
| SHA384 | 3 | wan24-Crypto |
| SHA512 | 4 | wan24-Crypto |
| **MAC** |  |  |
| HMAC-SHA1 | 0 | wan24-Crypto |
| HMAC-SHA256 | 1 | wan24-Crypto |
| HMAC-SHA384 | 2 | wan24-Crypto |
| HMAC-SHA512 | 3 | wan24-Crypto |
| **KDF** |  |  |
| PBKDF2 | 0 | wan24-Crypto |

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

and exports some helper methods, which are being used internal (you don't need 
to use them unless you have to). If you want the additional hybrid algorithms 
to be used every time, you can set the

- `EncryptionHelper.UseHybridOptions`
- `AsymmetricHelper.UseHybridKeyExchangeOptions`
- `AsymmetricHelper.UseHybridSignatureOptions`

to `true` to extend used `CryptoOptions` instances by the algorithms defined 
in the `HybridAlgorithmHelper` properties.

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
quantum safe algorithms, while currently no post quantum-safe asymmetric 
algorithms are implemented in this main library (`wan24-Crypto-BC` does).

## Disclaimer

`wan24-Crypto` and provided sub-libraries are provided "as is", without any 
warranty of any kind. Please read the license for the full disclaimer.

This library uses the available .NET cryptographic algorithms and doesn't 
implement any "selfmade" cryptographic algorithms. Extension libraries may add 
other well known third party cryptographic algorithm libraries, like Bouncy 
Castle.
