# Special features explained

## Flags and requirements

Using flags in the `CryptoOptions` you can define which information will be 
included (or are included, when decrypting) in the cipher header, while the 
requirements define which informations are required to be included in the 
cipher header when decrypting.

The flags ensure that all information which you require for decrypting cipher 
data is included in the header. If all necessary are included in the header, 
you can decrypt without specifying them in the options.

Requirements finally ensure that a cipher header contains all information, 
which is required for decryption. By defining requirements you can detect 
invalid cipher data before wasting time - and it's a security feature, too: 
Requirements can define additional security features, which you require to be 
applied before accepting cipher data for decryption.

## Skip the encryption header

Normally a header is prepended in the cipher data. In case you want to skip 
the header:

```cs
CryptoOptions options = new().IncludeNothing();
```

Including all required decryption information into the header ensures that 
you'll be able to decrypt the cipher even with newer library versions, or if 
you don't know the options used for encryption.

You may skip that header, if the cipher will be decrypted soon, and you know 
the options which are required for decryption.

## Forcing the MAC to cover the whole data

A cipher engine mode (like AES-CBC) may require to include a MAc which covers 
the whole data. Other cipher engines may not require that, but wan24-Crypto 
will cover the cipher header with a MAC to authenticate the included 
decryption options. The MAC will be validated before any decryption action, 
and during the cipher header is being red.

You may force to cover all cipher data instead, by setting the value of the 
`CryptoOptions.RequireMacCoverWhole` instance property to `true`. This will 
ensure that the included MAC covers the cipher header including the cipher 
data, which will add overhead for ciphers which don't require it - but add 
more security to the whole thing.

## Using `CryptoOptions` as cipher suite

You may use a configured `CryptoOptions` instance as storable crypto suite:

```cs
// Serialize for storing in binary form
byte[] serializedOptions = (byte[])options;

// Deserialize a previously stored binary form
options = (CryptoOptions)serializedOptions;
```

Sensible information (like keys) and temporary processing informations will be 
skipped by the serializer.

## Working with asymmetric keys

In general you should use these interfaces where possible:

- `IAsymmetricPrivateKey` for any private key
- `IAsymmetricPublicKey` for any public key
- `IKeyExchangePrivateKey` to enforce working with a private key with key 
exchange capabilities (extends `IAsymmetricPrivateKey`)
- `ISignaturePrivateKey` to enforce working with a private key with signature 
capabilities (extends `IAsymmetricPrivateKey`)
- `ISignaturePublicKey` to enforce working with a public key with signature 
validation capabilities (extends `IAsymmetricPublicKey`)

Work with final key types only, if you're sure that you won't switch to 
another algorithm later. The abstractions help you to stay flexible.

### Getting wan24-Crypto objects from .NET keys

wan24-Crypto uses the .NET cryptographic infrastructure and adds a higher 
level layer. But you're still able to access the lower level information, and 
it's also possible to create a higher level object from a lower level object:

```cs
// To determine the algorithm (and if the algorithm is supported)
IAsymmetricAlgorithm? algo = asymmetricAlgorithm.GetAsymmetricAlgorithm();

// Create a IAsymmetricPrivateKey instance from a .NET asymmetric algorithm
using IAsymmetricPrivateKey privateKey = asymmetricAlgorithm.GetAsymmetricPrivateKey();

// Create a IAsymmetricPublicKey instance from a .NET asymmetric algorithm
using IAsymmetricPrivateKey publicKey = asymmetricAlgorithm.GetAsymmetricPublicKey();
```

Supported are:

- Elliptic Curve Diffie Hellman
- Elliptic Curve DSA

### Getting wan24-Crypto objects from a X.509 certificate

The X.509 extensions try to 

- return the used wan24-Crypto asymmetric algorithm
- create a `IAsymmetricPrivateKey` instance
- create a `IAsymmetricPublicKey` instance

from a X.509 certificate, if possible. This is limited to the implemented .NET 
keys.

## Simple object (de)serialization

```cs
// Serialize
byte[] serializedData = (byte[])instance;

// Deserialize
instance = (InstanceType)serializedData;
```

This is possible with

- asymmetric keys
- `CryptoOptions`
- `KeyExchangeDataContainer`
- `SignatureContainer`

The used binary serializer uses object versioning to ensure that a previously 
serialized object can be deserialized later, even the object definition was 
changed meanwhile (or the serializer binary format).

## A payload object in the cipher header

You can include any payload object into the cipher header, but you should 
ensure to use a MAC, too, before deserializing or using a payload object 
instance from a cipher header (!):

```cs
CryptoOptions options = new CryptoOptions().WithPayload(payload);
```

**NOTE**: The payload will be serialized **unencrypted** to the cipher header!

To get the payload object later:

```cs
// Require payload to be included
CryptoOptions options = new()
{
	RequirePayload = true
};

// Read the cipher header
options = cipherData.ReadOptions(rawData, password, options);

// Extract the payload object
PayloadType payload = options.GetPayload<PayloadType>() ?? throw new InvalidDataException();

// Continue with decryption
cipherData.Decrypt(rawData, password, options);
```

In order to be able to (de)serialize the payload, the object should be JSON 
serializable or implement the `IStreamSerializer` interface. If you want to 
use the JSON serializer, you'll need to enable it, first:

```cs
EncryptionHelper.EnableJsonWrapper = true;
```

**CAUTION**: JSON (de)serializing is disabled per default for security 
reasons - enable on your own risk!

**CAUTION**: Even the Stream-Serializer-Extensions may let you run into 
security issues, if you change the default settings or implement insecure 
(de)serialization methods!

## Hybrid cryptography

In case you don't want to trust one algorithm alone (which may be broken in 
the future), you can add a counter algorithm for

- MAC (counter MAC will be created from the MAC)
- KDF (stretched key will be stretched twice using the counter KDF algorithm 
in the 2nd round)
- asymmetric key exchange (exchanged keys will be concatenated) and signature 
(signature will be signed with the counter signature algorithm)

The counter MAC will only authenticate the MAC, since creating two MACs over 
the whole authenticated data may be a too huge overhead. If you need that, 
you're free to DIY.

Using a counter KDF algorithm requires to store two salt values, which is only 
a little overhead compared to the security it adds.

Also the counter signature doesn't sign the whole authenticated data again, 
because this would produce too much overhead. Instead the first signature is 
signed, which authenticates the signed data reliable, as long as the hash 
algorithm wasn't broken.

### Counter hash

There's no counter hash, which you maybe would like to use for your 
signatures. It's easy to DIY:

```cs
// Apply a counter hash algorithm (SHA-512 in this example)
using MemoryStream ms = new();
using HashStreams hash = HashSha512Algorithm.Instance.GetHashStream(ms, options: new()
{
	LeaveOpen = true
});
ms.Write(dataToSign);
hash.Stream.Dispose();// To finalize the hash
ms.Write(hash.Transform.Hash!);

// Create and validate the signature

// Validate the counter hash algorithm
using MemoryStream ms = new(signedData);
using HashStreams hash = HashSha512Algorithm.Instance.GetHashStream(ms, writable: false, new()
{
	LeaveOpen = true
});
byte[] buffer = new byte[ms.Length - HashSha512Algorithm.Instance.HashLength];// Previously dataToSign
if(ms.Read(buffer) != buffer.Length) throw new IOException();
hash.Stream.Dispose();// Stop calculating the counter hash, 'cause the hashed data has been red already
byte[] bufferHash = new byte[HashSha512Algorithm.Instance.HashLength];
if(ms.Read(bufferHash) != bufferHash.Length) throw new IOException();
if(!hash.Transform.Hash!.AsSpan().SlowCompare(bufferHash))
	throw new InvalidDataException("Counter hash mismatch");
```

### Hybrid helper

The `HybridAlgorithmHelper` stores the default hybrid cryptography settings, 
which are missing per default:

- `KeyExchangeAlgorithm`: Hybrid key exchange algorithm to use
- `SignatureAlgorithm`: Hybrid signature algorithm to use
- `KdfAlgorithm`: Hybrid KDF algorithm to use
- `MacAlgorithm`: Hybrid MAC algorithm to use

If you want to use the hybrid default algorithms for encryption:

```cs
EncryptionHelper.UseHybridOptions = true;
```

These are examples for manual operations:

#### Hybrid PFS key exchange

Creating hybrid key exchange data:

```cs
CryptoOptions options = new CryptoOptions()
	.WithPfs(privateKey)// Optional give the peers PFS public key here
	.WithCounterKeyExchange(counterPrivateKey);// Optional give the peers counter PFS public key here
KeyExchangeDataContainer container = new()
{
	KeyExchangeData = privateKey.GetKeyExchangeData(options: options)
};
HybridAlgorithmHelper.GetKeyExchangeData(container, options);
```

The exchanged key is now available in `options.Password`.

For deriving an exchanged key:

```cs
CryptoOptions options = new CryptoOptions()
	.WithPfs(peerPrivateKey)
	.WithCounterKeyExchange(counterPeerPrivateKey);
HybridAlgorithmHelper.DeriveKey(container, options);
```

The exchanged key is now available in `options.Password`.

#### Hybrid KDF

```cs
CryptoOptions options = new CryptoOptions()
	.WithEncryptionAlgorithm()// Required for the desired key length
	.WithKdf()
	.WithCounterKdf();
options.Password = password.Stretch(EncryptionHelper.GetAlgorithm(options.Algorithm).KeySize, options);
HybridAlgorithmHelper.StretchPassword(options);
```

The final stretched password is now available in `options.Password`.

#### Hybrid MAC

```cs
CryptoOptions options = new CryptoOptions()
	.WithMac()
	.WithCounterMac();
options.Mac = authenticatedData.Mac(options);
HybridAlgorithmHelper.ComputeMac(options);
```

The final MAC is now available in `options.Mac`.

#### Hybrid signature

```cs
// Signing
CryptoOptions options = new CryptoOptions()
	.WithSignatureKey(privateKey, counterPrivateKey);
SignatureContainer = privateKey.SignData(dataToSign, options: options);

// Signature validation
publicKey.ValidateSignature(signature);
if(!HybridAlgorithmHelper.ValidateCounterSignature(signature))
	throw new InvalidDataException("Counter signature validation failed - signature is invalid!");
```

## Elliptic curves

Per default only these elliptic curves are supported:

- secp256r1
- secp384r1
- secp521r1

.NET offers way more elliptic curves, but not on all operating systems. To be 
compatible with all platforms, only the curves which are supported everywhere 
are supported (these curves are the NIST recommended curves).

There's no support for other (and custom) curves for several reasons:

- The support won't match this libraries target to make things more easy
- The NIST recommendations are worldwide used standards
- Custom curve support may blow up the cipher header overhead

## Post quantum-safety

AES-256 and (HMAC-)SHA-384+ are considered to be post quantum-safe at this 
time. Post quantum asymmetric algorithms aren't implemented in the core 
library, but they're available by using extension libraries. When you use such 
an extension library, you may want to force post quantum-safety for your 
application, which ensures that only post quantum-safe algorithms will be used 
per default:

```cs
CryptoHelper.ForcePostQuantumSafety(strict: true);
```

This will change the environment:

- Only post quantum-safe algorithms will be used in the defaults
- Hybrid algorithms will be enabled everywhere
- By giving `strict: true` to the method, post quantum-safety is strictly 
required (using any non-post quantum-safe algorithm will cause an exception)

If the method wasn't able to set post quantum-safe defaults in any area, it'll 
fail with an exception.
