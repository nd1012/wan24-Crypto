# wan24-Crypto

This library exports a generic high level crypto API, which allows to use and 
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

## How to get it

This library is available as 
[NuGet package](https://www.nuget.org/packages/wan24-Crypto/).

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

When using an asymmetric private key for encryption, a PFS key will be created 
when encrypting, and the cipher data can only be decrypted using the same 
private key again.

```cs
using IAsymmetricPrivateKey privateKey = AsymmetricHelper.CreateKeyExchangeKeyPair();
byte[] cipher = raw.Encrypt(privateKey);
byte[] raw = cipher.Decrypt(privateKey);
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

// Decryption (required to be decrypted within 10 seconds)
options = new()
{
    RequireTime = true,
    MaximumAge = TimeSpan.FromSeconds(10)
}
byte[] raw = cipher.Decrypt(password, options);
```

By defining `CryptoOptions.MaximumTimeOffset` you may define a time tolerance 
which is being used to be tolderant with peers having a slightly different 
system time.

### Asymmetric keys

#### Key exchange

```cs
// A: Create a key pair for key exchange and the key exchange data
using IAsymmetricPrivateKey privateKey = AsymmetricHelper.CreateKeyExchangeKeyPair();
byte[] keyExchangeData = privateKey.CreateKeyExchangeData();

// B: Create a key pair for key exchange, create the key exchange data and derive the key
using IAsymmetricPrivateKey privateKey2 = AsymmetricHelper.CreateKeyExchangeKeyPair();
byte[] key2 = privateKey2.DeriveKey(keyExchangeData);
byte[] keyExchangeData2 = privateKey2.CreateKeyExchangeData();

// A: Derive the key
byte[] key = privateKey.DeriveKey(keyExchangeData2);

Assert.IsTrue(key.SequenceEqual(key2));
```

The default key exchange algorithm is ECDH from a secp521r1 elliptic curve.

#### Digital signature

```cs
// Create a key pair for signature
using IAsymmetricPrivateKey privateKey = AsymmetricHelper.CreateSignatureKeyPair();
IAsymmetricPublicKey publicKey = privateKey.PublicKey;

// Sign data
SignatureContainer signature = privateKey.SignData(anyData);

// Validate a signature
publicKey.ValidateSignature(signature, anyData);
```

The default signature algorithm is DSA from a secp521r1 elliptic curve.

## Too many options?

The `CryptoOptions` contains a huge collection of properties, which follow a 
simple pattern: Which information should be included in the header, and is an 
information in the header required?

| Section | Property | Description |
| --- | --- | --- |
| Encryption | `Algorithm` | Encryption algorithm name |
| MAC | `MacAlgorithm` | MAC algorithm name |
|  | `MacIncluded` | Include a MAC in the header |
|  | `RequireMac` | Is the MAC required in the header? |
|  | `CounterMacAlgorithm` | Counter MAC algorithm name |
|  | `CounterMacIncluded` | Include a counter MAC in the header |
|  | `RequireCounterMac` | Is the counter MAC required in the header? |
|  | `ForceMacCoverWhole` | Force the MAC to cover all data |
|  | `RequireMacCoverWhole` | Is the MAC required to cover all data? |
| PFS / Key creation / Signature | `AsymmetricAlgorithm` | Asymmetric algorithm name |
|  | `AsymmetricAlgorithmIncluded` | Include the asymmetric algorithm in the header |
|  | `RequireAsymmetricAlgorithm` | Is the asymmetric algorithm required in the header? |
|  | `AsymmetricCounterAlgorithm` | Asymmetric counter algorithm name |
|  | `AsymmetricCounterAlgorithmIncluded` | Include the asymmetric counter algorithm in the header |
|  | `RequireAsymmetricCounterAlgorithm` | Is the asymmetric counter algorithm required in the header? |
|  | `KeyExchangeData` | Key exchange data (includes counter key exchange data; generated automatic) |
|  | `RequireKeyExchangeData` | Is the key exchange data required in the header? |
|  | `PrivateKey` | Private key for key exchange (set automatic) |
|  | `CounterPrivateKey` | Private key for counter key exchange (required when using a counter asymmetric algorithm) |
| KDF | `KdfAlgorithm` | KDF algorithm name |
|  | `KdfIterations` | KDF iteration count |
|  | `KdfSalt` | KDF salt (generated automatic) |
|  | `KdfAlgorithmIncluded` | Include the KDF information in the header |
|  | `RequireKdfAlgorithm` | Is the KDF information required in the header? |
|  | `CounterKdfAlgorithm` | Counter KDF algorithm name |
|  | `CounterKdfIterations` | Counter KDF iteration count |
|  | `CounterKdfSalt` | Counter KDF salt (generated automatic) |
|  | `CounterKdfAlgorithmIncluded` | Include the counter KDF information in the header |
|  | `RequireCounterKdfAlgorithm` | Is the counter KDF information required in the header? |
| Payload | `PayloadData` | Plain payload |
|  | `PayloadIncluded` | Is the payload object data included in the header? |
|  | `RequirePayload` | Is payload object data required in the header? |
| Serializer version | `SerializerVersion` | Serializer version number (set automatic) |
|  | `SerializerVersionIncluded` | Include the serializer version number in the header |
|  | `RequireSerializerVersion` | Is the serializer version number required in the header? |
| Header version | `HeaderVersion` | Header version number (set automatic) |
|  | `HeaderVersionIncluded` | Is the header version included in the header? |
|  | `RequireHeaderVersion` | Is the header version required in the header? |
| Encryption time | `Time` | Encryption timestamp (UTC) |
|  | `TimeIncluded` | Is the encryption time included in the header? |
|  | `RequireTime` | Is the encryption time required to be included in the header? |
|  | `MaximumAge` | Maximum age of cipher data (the default can be set to `DefaultMaximumAge`) |
|  | `MaximumTimeOffset` | Maximum time offset for a peer with a different system time (the default can be set to `DefaultMaximumTimeOffset`) |
| Compression | `Compressed` | Should the raw data be compressed before encryption? |
|  | `Compression` | The `CompressionOptions` instance to use |
| Hashing / Signature | `HashAlgorithm` | The name of the hash algorithm to use |
| Key creation | `AsymmetricKeyBits` | Key size in bits to use for creating a new asymmetric key pair |
| Stream options | `LeaveOpen` | Leave the processing stream open after operation? |

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
- `PrivateKey` (needs to be stored in another place)
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
using AsymmetricSignedPublicKey signedPublicRootKey = new()
{
    PublicKey = privateRootKey.PublicKey.GetCopy()
};
signedPublicRootKey.Sign(privateRootKey);

// Create a key pair, which will be signed
using ISignaturePrivateKey privateKey = AsymmetricHelper.CreateSignatureKeyPair();

// Sign the public key
using AsymmetricSignedPublicKey signedPublicKey = new()
{
    PublicKey = privateKey.PublicKey.GetCopy()
};
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

| Algorithm | ID |
| --- | --- |
| **Asymmetric cryptography** |  |
| ECDH | 0 |
| ECDSA | 1 |
| **Symmetric cryptography** |  |
| AES256CBC | 0 |
| **Hashing** |  |
| MD5 | 0 |
| SHA1 | 1 |
| SHA256 | 2 |
| SHA384 | 3 |
| SHA512 | 4 |
| **MAC** |  |
| HMAC-SHA1 | 0 |
| HMAC-SHA256 | 1 |
| HMAC-SHA384 | 2 |
| HMAC-SHA512 | 3 |
| **KDF** |  |
| PBKDF2 | 0 |

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
to be used every time, you can set the `EncryptionHelper.UseHybridOptions` to 
`true` to extend used `CryptoOptions` instances by the algorithms defined in 
the `HybridAlgorithmHelper` properties.

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
quantum safe algorithms.

## Disclaimer

`wan24-Crypto` and provided sub-libraries are provided "as is", without any 
warranty of any kind. Please read the license for the full disclaimer.

This library uses the available .NET cryptographic algorithms and doesn't 
implement any "selfmade" cryptographic algorithms. Extension libraries may add 
other well known third party cryptographic algorithm libraries, like NaCl or 
Bouncy Castle.
