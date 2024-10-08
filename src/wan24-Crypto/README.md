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
| | SHA3-256 |
| | SHA3-384 |
| | SHA3-512 |
| | Shake128 |
| | Shake256 |
| **MAC** | HMAC-SHA-1 |
|  | HMAC-SHA-256 |
|  | HMAC-SHA-384 |
|  | HMAC-SHA-512 |
|  | HMAC-SHA3-256 |
|  | HMAC-SHA3-384 |
|  | HMAC-SHA3-512 |
| **Symmetric encryption** | AES-256-CBC (ISO10126 padding) |
| **Asymmetric keys** | Elliptic Curve Diffie Hellman |
|  | Elliptic Curve DSA (RFC 3279 signatures) |
| **KDF key stretching** | PBKDF#2 (250,000 iterations per default) |
|  | SP 800-108 HMAC CTR KBKDF |

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

- [wan24-Crypto-BC (adopts some algorithms from Bouncy Castle)](https://www.nuget.org/packages/wan24-Crypto-BC/)
- [wan24-Crypto-NaCl (adopts the Argon2id KDF algorithm from NSec)](https://www.nuget.org/packages/wan24-Crypto-NaCl/)
- [wan24-Crypto-TPM (simplifies including TPM into your apps security)](https://www.nuget.org/packages/wan24-Crypto-TPM/)

## Usage

In case you don't use the `wan24-Core` bootstrapper logic, you need to 
initialize the library first:

```cs
wan24.Crypto.Bootstrap.Boot();
```

In case you work with dependency injection (DI), you may want to add some 
services:

```cs
builder.Services.AddWan24Crypto();
```

**WARNING**: The factory default algorithms may not be available on every 
platform! The `wan24-Crypto-BC` extension library contains pure .NET 
implementations of most algorithms from `wan24-Crypto`, which can be used 
instead.

### Hashing

```cs
byte[] hash = rawData.Hash();
```

The default hash algorithm ist SHA3-512.

#### Shake128/256 hash algorithms

The Shake128 and Shake256 hash algorithms support a variable output (hash) 
length. The default output length of the hash implementations of 
`wan24-Crypto` is

- 32 bytes for Shake128
- 64 bytes for Shake256

when using the `HashHelper`, the extension methods, or the 
`HashShake128/256Algorithm` instances directly.

Anyway, if you need other output lengths, you may use the 
`NetShake128/256HashAlgorithmAdapter` classes, which allow to give the desired 
output length in bytes (a multiple of 8) to the constructor, and can be used 
as every other .NET `HashAlgorithm` implementation (also in a crypto 
stream/transform, for example).

### MAC

```cs
byte[] mac = rawData.Mac(password);
```

The default MAC algorithm is HMAC-SHA3-512.

**NOTE**: The `CryptoOptions.MacPassword` won't be used here, since you have 
to specify the MAC password in the method call already. The `MacPassword` is 
only used during encryption, if it is different from the encryption key.

### KDF (key stretching)

```cs
(byte[] stretchedPassword, byte[] salt) = password.Stretch(len: 64);
```

The default KDF algorithm is PBKDF#2, using 250,000 iterations, with a salt 
length of 16 byte and SHA3-384 for hashing.

**TIP**: You may override the default hash algorithm which is being used in a 
new options instance in the static `KdfPbKdf2Options.DefaultHashAlgorithm` 
property.

Example options usage:

```cs
(byte[] stretchedPassword, byte[] salt) = password.Stretch(len: 64, options: new KdfPbKdf2Options()
    {
        HashAlgorithm = HashSha3_512Algorithm.ALGORITHM_NAME
    });// KdfPbKdf2Options cast implicit to CryptoOptions
```

**NOTE**: The SP 800-108 HMAC CTR KBKDF algorithm isn't available in a WASM 
app, and there's currently no pure .NET replacement included in the 
`wan24-Crypto-BC` library. It doesn't support iterations and salt (but a label 
and context value instead). Not all hash algorithms may be supported (you'll 
need to register custom hash algorithms to the .NET `CryptoConfig`).

### Encryption

```cs
byte[] cipher = raw.Encrypt(password);
byte[] decrypted = cipher.Decrypt(password);
```

There are extension methods for memory and streams.

The default algorithms used:

| Usage | Algorithm |
| --- | --- |
| Symmetric encryption | AES-256-CBC |
| MAC | HMAC-SHA3-512 |
| KDF | PBKDF#2 |
| Asymmetric key exchange | EC Diffie Hellman |
| Asymmetric digital signature | EC DSA |

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
byte[] decrypted = cipher.Decrypt(privateKey);
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
byte[] decrypted = cipher.Decrypt(peerPrivateKey, options);
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
byte[] decrypted = cipher.Decrypt(password, options);
```

By defining `CryptoOptions.MaximumTimeOffset` you may define a time tolerance 
which is being used to be tolerant with peers having a slightly different 
system time.

#### Password pre-processing

The `CryptoOptions.EncryptionPassword(Async)PreProcessor` delegates may pre-
process an encryption password from `CryptoOptions.Password` before the key 
bytes are being finalized for use with the desired crypto engine. Key 
derivation from asymmetric keys and KDF are being applied before.

The asynchronous delegate will only be used during asynchronous operations, 
while the synchronous delegate is a fallback during asynchronous operations, 
if no asynchronous delegate was set.

The delegate itself need to set the final key to use to 
`CryptoOptions.Password` and should clear the current value.

**TIP**: For setting a new password to `CryptoOptions.Password` use the 
`CryptoOptions.SetNewPassword` method. This method will clear the previous 
value, if any.

### Asymmetric keys

#### Key exchange

PFS example:

```cs
// A: Create a key pair
using IKeyExchangePrivateKey privateKeyA = AsymmetricHelper.CreateKeyExchangeKeyPair();
byte[] publicKeyData = (byte[])privateKeyA.PublicKey.Export();// publicKeyData needs to be available at B

// B: Create a key pair, key exchange data and derive the shared key
using IAsymmetricPublicKey publicKeyA = AsymmetricKeyBase.Import<IAsymmetricPublicKey>(publicKeyData);// Deserialize the peers public key of any format
using IKeyExchangePrivateKey privateKeyB = AsymmetricHelper.CreateKeyExchangeKeyPair(new()
{
    AsymmetricAlgorithm = publicKeyA.Algorithm.Name,
    AsymmetricKeyBits = publicKeyA.Bits
});
(byte[] keyB, byte[] keyExchangeData) = privateKeyB.GetKeyExchangeData(publicKeyA);// keyExchangeData needs to be available at A

// A: Derive the exchanged key
byte[] keyA = privateKeyA.DeriveKey(keyExchangeData);

Assert.IsTrue(keyA.SequenceEquals(keyB));
```

The default key exchange algorithm is ECDH from a secp521r1 elliptic curve.

##### `IKeyExchange` interface

All asymmetric private keys which can be used for a key exchange implement the 
`IKeyExchange` interface. This interface is also used for PAKE, for example. 
By working with this interface, it's possible to implement more abstract key 
exchange routines:

```cs
// Initiator side
(byte[] keyA, byte[] keyExchangeData) = initiatorKeyExchangeProcessor.GetKeyExchangeData();

// Transfer keyExchangeData to the peer using a secure communication channel

// Peer side
byte[] keyB = peerKeyExchangeProcessor.DeriveKey(keyExchangeData);

Assert.IsTrue(keyA.SequenceEquals(keyB));
```

`initiatorKeyExchangeProcessor` and `peerKeyExchangeProcessor` are 
`IKeyExchange` instances and may be an asymmetric private key, or a PAKE 
instance, for example.

Both peers need to agree to the same key exchange method, first. And both 
peers need to use a key exchange processor which can produce/take the key 
exchange data of the initiator.

**NOTE**: The `PrivateKeySuite` implements `IKeyExchange` using the managed 
`KeyExchangeKey`, if any.

#### Digital signature

```cs
// Create a key pair for signature
using ISignaturePrivateKey privateKey = AsymmetricHelper.CreateSignatureKeyPair();

// Sign data
SignatureContainer signature = privateKey.SignData(anyData);

// Validate a signature
privateKey.PublicKey.ValidateSignature(signature, anyData);
```

The default signature algorithm is ECDSA from a secp521r1 elliptic curve.

### Value protection

The `ValueProtection` contains some static methods for protecting a value in a 
specified scope:

```cs
value = ValueProtection.Protect(value);
value = ValueProtection.Unprotect(value);
```

There are 3 scopes, which may be given as parameter:

- `System`: System (permanent system bound protection)
- `User`: Current user (permanent user bound protection)
- `Process`: Current process (default; for non-permanent protection only!)

The scope keys will be set automatic, but may be replaced with your own logic. 
Per default the keys are generated like this:

- `System`: Hash of application location and machine name
- `User`: Hash of user domain and name, application location and machine name
- `Process`: Random data

**WARNING**: Setting new keys isn't thread-safe!

The `Protect` and `Unprotect` methods are delegate properties which can be 
exchanged. For example for Windows and Linux OS you may want to use different 
approaches.

For protecting a value it'll be encrypted using the current default encryption 
options.

Using the `ValueProtectionLevels` you can manage keys for a specific security 
requirement by defining keys using the `ValueProtectionKeys.Set` method, and 
getting them later using the `ValueProtectionKeys.Get` method. The protection 
levels include variations for the system (mashine) and user level, with or 
without TPM (for TPM usage the `wan24-Crypto-TPM` module is required) and 
optional with an online key storage and/or a manual entered user password 
(the online key storage and user password input needs to be implemented by 
yourself):

```cs
// userPassword should be entered manually whenever it's required to (un)protect a value

byte[] protectedValue = ValueProtectionLevels.UserTpmPassword.Protect(value, userPassword);
// protectedValue is ready to be stored for the current user scope

byte[] unprotectedValue = ValueProtectionLevels.UserTpmPassword.Unprotect(protectedValue, userPassword);
```

The `ValueProtectionKeys` is used to (re)store a protection key for each level 
using the `Set(2)` and `(Try)Get` methods. It uses a `ISecureValue` for 
serious key protection:

```cs
ValueProtectionKeys.Set(ValueProtectionLevels.UserTpmPassword, protectionKey, userPassword);
```

**NOTE**: While the `Set` method requires a `ISecureValue`, the `Set2` method 
creates a `SecureValue` from the `protectionKey` byte array parameter. The 
`(Try)Get` methods will return the final key to use (after MAC, if 
applicable). Stored keys will be protected for the according scope using 
`ValueProtection`.

You may use the extension method `ValueProtectionLevels.*.Protect/Unprotect` 
for protecting/unprotecting a value, or the raw protection key which is being 
returned from the `ValueProtectionKeys.(Try)Get` methods for applying 
en-/decryption of values by yourself.

To determine the capabilities of a protection level, you can use these 
`ValueProtectionLevels` extension methods:

- `RequiresPasswordInput`: If a manual entered user password is required
- `RequiresTpm`: If a TPM is required
- `RequiresNetwork`: If an online key storage is required
- `GetScope`: Determines the according `ValueProtection.Scope` enumeration 
value

**NOTE**: In order to be able to use the TPM protection levels, 
`wan24-Crypto-TPM` and a TPM must be available. The protection levels 
including online communication require implementing an online key storage 
service. `ValueProtectionKeys` does support a single user context only (it's 
designed for an app which runs in a specific user context).

**WARNING**: For each value protection level that you want to use you'll need 
to set a key using `ValueProtectionKeys.Set(2)`, which is not thread-safe.

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
|  | `EncryptionOptions` | String serialized encryption options | `null` |
|  | `MaxCipherDataLength` | Maximum cipher data length in bytes | `null` |
|  | `EncryptionPasswordPreProcessor` | Delegate for pre-processing an encryption password (the default can be set to `DefaultEncryptionPasswordPreProcessor`) | `null` |
|  | `EncryptionPasswordAsyncPreProcessor` | Delegate for pre-processing an encryption password (only applied during asynchronous operation; the default can be set to `DefaultEncryptionPasswordAsyncPreProcessor`) | `null` |
|  | `FlagsIncluded` | Are the flags included in the header? | `true` |
|  | `RequireFlags` | Are the flags required to be included in the header? | `true` |
|  | `PrivateKeysStore` | Private keys store to use for decryption, using automatic key suite revision selection (the default can be set to `DefaultPrivateKeysStore`) | `null` |
|  | `PrivateKeyRevision` | Revision of the used private key suite (may be set automatic) | `0` |
|  | `PrivateKeyRevisionIncluded` | Is the private key suite revision included in the header? | `true`, if a `DefaultPrivateKeysStore` was set |
|  | `RequirePrivateKeyRevision` | Is the private key suite revision required to be included in the header? | `true`, if a `DefaultPrivateKeysStore` was set |
|  | `RngSeeding` | RNG seeding options (overrides `RND.AutoRngSeeding`) | `null` |
| MAC | `MacAlgorithm` | MAC algorithm name | `null` (`HMAC-SHA3-512`) |
|  | `MacIncluded` | Include a MAC in the header | `true` |
|  | `RequireMac` | Is the MAC required in the header? | `true` |
|  | `CounterMacAlgorithm` | Counter MAC algorithm name | `null` |
|  | `CounterMacIncluded` | Include a counter MAC in the header | `false` |
|  | `RequireCounterMac` | Is the counter MAC required in the header? | `false` |
|  | `ForceMacCoverWhole` | Force the MAC to cover all data | `false` |
|  | `RequireMacCoverWhole` | Is the MAC required to cover all data? | `false` |
|  | `MacPassword` | Password to use for a MAC | `null` |
| Encryption / Key creation / Signature | `AsymmetricAlgorithm` | Asymmetric algorithm name | `null` (`ECDH` for encryption, `ECDSA` for signature) |
|  | `AsymmetricAlgorithmOptions` | String serialized algorithm options | `null` |
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
| Hashing / Signature | `HashAlgorithm` | The name of the hash algorithm to use | `null` (`SHA3-512`) |
| Key creation | `AsymmetricKeyBits` | Key size in bits to use for creating a new asymmetric key pair | `1` |
| Stream options | `LeaveOpen` | Leave the processing stream open after operation? | `false` |
| Key usage counting options | `KeySuite` | Private key suite to use for key usage counting | `null` |
| Debug options | `Tracer` | Collects tracing information during en-/decryption | `null` |
| Tag | `Tag` | Can store any tagged object which will be cloned on `GetCopy`, if `IClonable` is implemented | `null` |

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
- Key usage counting options

In case you want to use the `*Counter*` options, you'll need to set the 
`CounterPrivateKey` value.

For MAC these sections matter:

- MAC
- Stream options

For hashing these sections matter:

- Hashing
- Stream options

For asymmetric key creation these sections matter:

- Key creation
- Key usage counting options

For signature these sections matter:

- Signature
- Hashing
- Stream options
- Key usage counting options

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

You could implement a JSON configuration file using the `AppConfig` logic from 
`wan24-Core`, and the `CryptoAppConfig`. In this configuration it's possible 
to define many options from the `CryptoEnvironment.Options`, which can be 
written as a JSON value. There it's also possible to define disabled 
algorithms, which makes it possible to react to a broken algorithm very fast 
and without having to update your app, for example.
If you use an `AppConfig`, it could look like this:

```cs
public class YourAppConfig : AppConfig
{
    public YourAppConfig() : base() { }

    [AppConfig(AfterBootstrap = true)]
    public CryptoAppConfig? Crypto { get; set; }
}

await AppConfig.LoadAsync<YourAppConfig>();
```

**NOTE**: If you use the `CompressionAppConfig` also, it should be applied 
before the `CryptoAppConfig` by defining a `Priority` in the 
`AppConfigAttribute`.

In the `config.json` in your app root folder:

```json
{
    "Crypto":{
        ...
    }
}
```

Anyway, you could also place and load a `CryptoAppConfig` in any configuration 
which supports using that custom type.

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
- `KeySuite` (needs to be stored in another place)
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
- `Tag`

Also delegates won't be serialized.

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
| PkiSig | Permitted to sign sub-keys |
| KePublicKey | Identifier of the public key for the key exchange with the owner |
| KePublicCounterKey | Identifier of the public counter key for the key exchange with the owner |
| SigPublicKey | Identifier of the public signature key of the owner |
| SigPublicCounterKey | Identifier of the public signature counter key of the owner |
| CipherSuite | Serialized `CryptoOptions` to use with the signed key owner |
| Serial | Serial number (the key revision of the owner context) |

Some key meta data like the creation and expiration time, or a nonce, is 
included in a lower level in the `AsymmetricSignedPublicKey` already, and 
don't need to appear in the signed attribute list again.

A key signing request may also contain more attributes than the final signed 
key, if you want to give signing instructions to the PKI. The PKI may 
remove/replace/extend those instructions for signing.

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

For validating the signed attributes of a signing request or a signed key, you 
can use the `SignedAttributes.Validate(Async)` methods. Using the 
`SignedAttributes.ValidationOptions` you can specify common restrictions for 
the above listed default attributes. The validation will be executed also, if 
`AsymmetricSignedPublicKey.Validate(Async)` was called. For additional 
attribute validations you can set 
`SignedAttributes.AdditionalValidation(Async)` handlers. If no public key 
suite store was given, key exchange/signature keys will be looked up in the 
PKI, which was given in the options (`CryptoEnvironment.PKI` is being used per 
default).

## Key ring

The `KeyRing` type can store these key types:

- Symmetric key (a byte sequence)
- Asymmetric key
- Key suite
- Key suite store
- PAKE record
- PAKE record store
- PKI

In addition different `CryptoOptions` can be stored to a name.

Every key will be stored with a unique name, which is required to get the key 
later:

```cs
// Create a new key ring
using KeyRing keys = new();

// Add a key
if(!keys.TryAdd("name", anyKey))
    throw new Exception("Key exists already");

// Get a key
if(!keys.TryGetSymmetric("name", out anyKey))
    throw new Exception("Key not found");

// Encrypt/decrypt
byte[] keyBytes = keys.Encrypt(secret);
// Can be restored using `KeyRing.Decrypt(keyBytes, secret)`
```

Adding, updating, getting, removing keys and encryption is thread safe.

The static `MaxCount` and `MaxSymmetricKeyLength` properties limit the max. 
number of stored keys and the max. symmetric key length in bytes. A key name 
is limited to 255 characters.

**NOTE**: If a key ring uses algorithms or types which are not available in a 
deserializing context, it can't be restored anymore!

In order to ignore unusable keys during deserialization use the constructor 
which takes `ignoreSerializationErrors` and set the value to `true`:

```cs
using KeyRing keys = new(ignoreSerializationErrors: true);
int serializerVersion = stream.ReadSerializerVersion();
((IStreamSerializer)keys).Deserialize(stream, serializerVersion);
```

It's assumed that `stream` contains the decrypted key ring serialization data 
already.

**NOTE**: Only type/algorithm incompatibilities will be ignored by skipping 
the stored object. Serialized structure errors will still throw.

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

### PAKE with http requests

PAKE can encrypt http messages and provide an additional authentication to a 
JWT. Benefits of encrypting http messages:

- additional authentication to JWT
- Perfect Forward Secrecy (PFS) encryption for every single http request
- nothing from the request can be sniffed from a man in the middle (MiM)
- the request can't be repeated in another authentication context
- you can implement replay attack avoiding measures by denying the same random 
data (from the PAKE authentication object) within a timespan

The final http method, request path, headers and body are completely hidden to 
any attacker who may be able to sniff your network traffic. Also in a client 
browser the developer tools won't show any request details, which is perfect 
in a WASM app to hide even your servers API effectively.

Of course processing each request and response with PAKE has an overhead, 
especially when using compression, too.

Example client code:

```cs
using PakeHttpRequestFactory factory = new(username, password);
using PakeRequest request = await factory.CreateRequestAsync(
    new("https://domain.tld"), 
    HttpMethod.Get, 
    "/request/path"
    );
// request.Request contains the http request message
using PakeResponse response = await httpResponseMessage.GetPakeResponseAsync(request.Key);
// response.Response contains the decoded PAKE response, response.Body.CryptoStream the response stream
response.Response.EnsureSuccessStatusCode();
```

The server needs to process messages, too, of course. This part isn't included 
within this library and does vary depending on the webserver.

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

#### Some words on secure seeding

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

### Entropy monitoring

The `(Disposable)EntropyMonitor` can monitor the entropy of produced RND and 
enforce a minimum required entropy using available algorithms from 
`EntropyHelper`. The monitor simply wraps an `IRng` for this and adds entropy 
checks for produced RND before returning.

**CAUTION**: If you didn't set a `MaxRetries` value larger than zero, a wrong 
`EntropyHelper` configuration could cause system exhaustion when RND was 
requested.

## Password helper

Using the `PasswordHelper` you can easily generate and validate passwords:

```cs
string pwd = new(PasswordHelper.GeneratePassword());
Assert.AreEqual(PasswordOptions.None, PasswordHelper.CheckPassword(pwd, PasswordOptions.Lower));
```

The `PasswordOptions` flags allow to specify password requirements for the 
generator and the validation. These options are available for generating a 
password:

- Length
- Entropy validation
- Lower case character set
- Upper case character set
- Numeric character set
- Special character set

All used character sets may be customized as required.

The generator can

- use any password length
- use a lower case character set
- use an upper case character set
- use a numeric character set
- use a special character set
- validate the entropy of the generated password

while the validation checks

- password length restrictions
- a minimum entropy
- for lower case characters
- for upper case characters
- for numeric characters
- for special characters

All those options can be mixed up using the `PasswordOptions` as required.

The `CheckPassword` returns `PasswordOptions.None` on success. Any other 
return value contains a flag for each found problem with the given password.

## Password post-processing

An entered user password may be easy to break using brute force. For this 
reason it's recommended to apply at last KDF on the raw password. The 
`PasswordPostProcessor` base type allows to create a reuseable post-processor, 
which can also be used for pre-processing an encryption password. 
`PasswordPostProcessorChain` does apply a chain of `PasswordPostProcessor` in 
sequential order.

The `PasswordPostProcessor.Instance` is a ready-to-use post-processor, which 
does these steps for processing a password:

1. apply KDF
2. apply a counter KDF, if configured
3. compute a MAC, if configured

For a fully customized processing you can use the static 
`DefaultPasswordPostProcessor.ProcessPwd` method, which allows giving the 
processing options to use as an argument.

You're free to set your own default processor to 
`PasswordPostProcessor.Instance` (which will be used when calling 
`WithEncryptionPasswordPreProcessing` on `CryptoOptions` without any argument 
values).

The `CryptoEnvironment.Options` have a property `PasswordPostProcessors` for 
storing password post-processor instances which are used to build a 
`PasswordPostProcessorChain`, which will be set to 
`PasswordPostProcessor.Instance`. If the property 
`UsePasswordPostProcessorsInCryptoOptions` was set to `true`, its methods will 
be set to `CryptoOptions.DefaultEncryptionPassword(Async)PreProcessor`.

For the `CryptoAppConfig` it's the same logic, except that you need to define 
the CLR type names including namespace to the `PasswordPostProcessors` 
property. The password post-processors need a parameterless constructor in 
order to be able to be used in this context.

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

### Automatic key ecryption key providing

Implement the `IEncryptPropertiesKek` interface for automatic key encryption 
key (KEK) providing. The object needs to implement a data encryption key (DEK) 
property with a `DekAttribute`. Then you can use the `AutoEn/DecryptObject` 
extension methods.

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
| Ed25519 | 8 | wan24-Crypto-BC |
| Ed448 | 9 | wan24-Crypto-BC |
| X25519 | 10 | wan24-Crypto-BC |
| X448 | 11 | wan24-Crypto-BC |
| XEd25519 | 12 | wan24-Crypto-BC |
| XEd448 | 13 | wan24-Crypto-BC |
| Streamlined NTRU Prime | 14 | wan24-Crypto-BC |
| BIKE | 15 | wan24-Crypto-BC |
| HQC | 16 | wan24-Crypto-BC |
| Picnic | 17 | wan24-Crypto-BC |
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
| SHA3-256 | 5 | wan24-Crypto |
| SHA3-384 | 6 | wan24-Crypto |
| SHA3-512 | 7 | wan24-Crypto |
| Shake128 | 8 | wan24-Crypto |
| Shake256 | 9 | wan24-Crypto |
| **MAC** |  |  |
| HMAC-SHA-1 | 0 | wan24-Crypto |
| HMAC-SHA-256 | 1 | wan24-Crypto |
| HMAC-SHA-384 | 2 | wan24-Crypto |
| HMAC-SHA-512 | 3 | wan24-Crypto |
| HMAC-SHA3-256 | 4 | wan24-Crypto |
| HMAC-SHA3-384 | 5 | wan24-Crypto |
| HMAC-SHA3-512 | 6 | wan24-Crypto |
| TPMHMAC-SHA-1 | 7 | wan24-Crypto-TPM |
| TPMHMAC-SHA-256 | 8 | wan24-Crypto-TPM |
| TPMHMAC-SHA-384 | 9 | wan24-Crypto-TPM |
| TPMHMAC-SHA-512 | 10 | wan24-Crypto-TPM |
| **KDF** |  |  |
| PBKDF#2 | 0 | wan24-Crypto |
| Argon2id | 1 | wan24-Crypto-NaCl |
| SP 800-108 HMAC CTR KBKDF | 2 | wan24-Crypto |

PAKE has no algorithm ID, because it doesn't match into any category (there is 
no PAKE multi-algorithm support implemented), and it's a key exchange 
protocol - but not a cryptographic algorithm.

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

## Key usage counting

Some algorithms have an usage limit. After that limit was exceeded, a 
(private) key should be renewed. `wan24-Crypto` supports key usage counting 
for keys which are managed in a `PrivateKeySuite`. To count key usage, set 
the private key suite instance to the `CryptoOptions.KeySuite`.

**CAUTION**: Key usage can't be counted for asymmetric private keys, if the 
raw key derivation or raw hash signature methods are called directly, 'cause 
the methods don't use `CryptoOptions`. Before using those methods directly, 
please call any `PrivateKeySuite.Count*KeyUsage` method by yourself.

If the key usage was exceeded, a `KeyUsageExceededException` will be thrown 
on any attempt to use the key once more.

**NOTE**: Different algorithms have different key usage count limits. Those 
are defined in their `MAX_KEY_USAGE_COUNT` constants, IF there's any limit.

## Post quantum safety

Some of the used cryptographic algorithms are quantum safe already, but 
especially the asymmetric algorithms are not post quantum safe at all. If you 
use an extension library which offers asymmetric post quantum safe algorithms 
for key exchange and signature, you can enforce post quantum safety for all 
used default algorithms by calling `CryptoHelper.ForcePostQuantumSafety`. This 
method will ensure that all used default algorithms are post quantum safe. In 
case it's not possible to use post quantum algorithms for all defaults, this 
method will throw an exception.

**NOTE**: AES-256, and SHA-384+, SHA3 and Shake128/256 (and HMAC-SHA-384+ and 
HMAC-SHA3-*) are considered to be post quantum-safe algorithms, while 
currently no post quantum-safe asymmetric algorithms are implemented in this 
main library (`wan24-Crypto-BC` does implement some), since .NET doesn't offer 
any API (this may change with coming .NET releases).

**NOTE**: While SHA3 and Shake128/256 (KECCAK) was designed for post quantum 
safety, AES-256 and SHA-384+ (SHA2) wasn't and is only considered to be post 
quantum safe because of its key/output length (this also applies to the 
HMACs). While the post quantum safety of SHA3 and Shake218/256 should stay 
stable, key/output length based considerations may be reconsidered from time 
to time, based on the recent quantum computing capabilities available.

## Disclaimer

`wan24-Crypto` and provided sub-libraries are provided "as is", without any 
warranty of any kind. Please read the license for the full disclaimer.

This library uses the available .NET cryptographic algorithms and doesn't 
implement any "selfmade" cryptographic algorithms. Extension libraries may add 
other well known third party cryptographic algorithm libraries, like Bouncy 
Castle. Also "selfmade" cryptographic algorithms may be implemented as 
extensions.
