# Implementing more algorithms

wan24-Crypto is designed to make it easy to implement any cryptographic 
algorithm, which may be available from a third party library. This document 
gives tips how to implement new algorithms for use with the wan24-Crypto 
library.

Please be sure to use algorithm values >255 to avoid conflicts with official 
extensions.

## Making your extension official

If you want your extension to become official, please be sure to match the pre-
requirements:

1. Make your source code open source (and forkable) on GitHub
1. Create a test project which uses the 
[shared tests NuGet package](https://www.nuget.org/packages/wan24-Crypto-Shared-Tests/) 
and be sure to execute the tests which match your implementations

Then there are just a few more steps:

1. Request your official algorithm IDs (you can open an issue for that) and 
provide the URI to your GitHub project
1. Update your extension to use your official algorithm IDs
1. Create a NuGet package
1. Update the issue with the URI to the NuGet package and request publication
1. Wait for submission approval

That's it! Your benefit will be a link to your NuGet package on the 
wan24-Crypto GitHub project main page, and official algorithm values, which 
won't conflict with other future developments ever.

In order to keep your official algorithm values please be sure to

- update your project and NuGet package when the main wan24-Crypto NuGet 
package was updated
- update your project and NuGet package when your implemented algorithm(s) 
were updated

Dead projects will loose their official algorithm value assignments after a 
deprecation period of one year. The deprecation period starts when 
wan24-Crypto was updated, and you didn't update your project and/or NuGet 
packet, or an implemented algorithm was broken.

If your implemented encryption algorithm has been broken, wan24-Crypto will be 
updated to ensure that this algorithm can't be applied anymore (only 
decryption will work).

## Implemting a hash algorithm

Your implementation needs to extend the `HashAlgorithmBase` type and implement 
these abstrations:

- `HashLength`: Property which returns the hash length in bytes
- `IsPostQuantum`: If the algorithm is considered to be post quantum-safe
- `GetHashAlgorithm`: Returns a new `HashAlgorithm` instance

Registration:

```cs
HashHelper.Algorithms["YourAlgorithm"] = new YourAlgorithm();
```

Tests:

```cs
await wan24.Crypto.Tests.HashingTests.TestAllAlgorithms();
```

## Implementing a MAC algorithm

Your implementation needs to extend the `MacAlgorithmBase` type and implement 
these abstrations:

- `MacLength`: Property which returns the MAC length in bytes
- `IsPostQuantum`: If the algorithm is considered to be post quantum-safe
- `GetMacAlgorithm`: Returns a new `KeyedHashAlgorithm` instance

Registration:

```cs
MacHelper.Algorithms["YourAlgorithm"] = new YourAlgorithm();
```

Tests:

```cs
await wan24.Crypto.Tests.MacTests.TestAllAlgorithms();
wan24.Crypto.Tests.HybridTests.AllMacTests();
```

## Implementing a KDF algorithm

Your implementation needs to extend the `KdfAlgorithmBase` type and implement 
these abstrations:

- `DefaultIterations`: The number of default iterations
- `SaltLength`: Returns the required salt length in bytes
- `IsPostQuantum`: If the algorithm is considered to be post quantum-safe
- `Stretch`: Key stretching method which return the stretched key and the used 
salt

Registration:

```cs
KdfHelper.Algorithms["YourAlgorithm"] = new YourAlgorithm();
```

Tests:

```cs
wan24.Crypto.Tests.KdfTests.TestAllAlgorithms();
wan24.Crypto.Tests.HybridTests.AllKdfTests();
```

## Implementing a symmetric encryption algorithm

Your implementation needs to extend the `EncryptionAlgorithmBase` type and 
implement these abstractions:

- `KeySize`: The required key size in bytes
- `IvSize`: The required IV size in bytes
- `BlockSize`: The block size in bytes
- `RequireMacAuthentication`: If a MAC authentication is required
- `GetEncryptor(Async)`: Returns a `IcryptoTransform` for encryption and 
writes all information to the cipher stream, which is required for creating a 
decryptor (such as IV bytes, etc.)
- `GetDecryptor(Async)`: Returns a `IcryptoTransform` for decryption and 
reads all information from the cipher stream, which is required for creating 
the decryptor (such as IV bytes, etc.)

Registration:

```cs
EncryptionHelper.Algorithms["YourAlgorithm"] = new YourAlgorithm();
```

Tests:

```cs
await wan24.Crypto.Tests.EncryptionTests.TestAllAlgorithms();
wan24.Crypto.Tests.HybridTests.AllSyncEncryptionTests();
await wan24.Crypto.Tests.HybridTests.AllAsyncEncryptionTests();
```

## Implementing an asymmetric algorithm

You'll need to create at last these types:

- Algorithm definition which extends `AsymmetricAlgorithmBase`
- Private key which extends `AsymmetricPrivateKeyBase`
- Public key which extends `AsymmetricPublicKeyBase`

If the algorithm is for key exchange, the private key needs to implement the 
`IKeyExchangePrivateKey` interface.

If the algorithm is for signature, the private key needs to implement the 
`ISignaturePrivateKey` interface, while the public key needs to implement the 
`ISignaturePublicKey` interface.

An asymmetric may be used for both, key exchange and signature.

**NOTE**: Your private/public key implementations need to store the serialized 
key data in the `KeyData` property!

Registration:

```cs
AsymmetricHelper.Algorithms["YourAlgorithm"] = new YourAlgorithm();
```

Tests:

```cs
wan24.Crypto.Tests.AsymmetricTests.TestAllAlgorithms();
wan24.Crypto.Tests.HybridTests.AllAsymmetricTests();
```

### Implementing the algorithm definition

```cs
public sealed class YourAsymmetricAlgorithm extends AsymmetricAlgorithmBase<YourPublicKey, YourPrivateKey>
{
	public YourAsymmetricAlgorithm() : base("YourAlgorithmName", 123)
		=> _DefaultOptions.AsymmetricKeyBits = DefaultKeySize = 123;

	...
}
```

You'll need to implement these abstractions:

- `Usages`: Returns the supported key usages (key exchange and/or signature)
- `IsEllipticCurveAlgorithm`: If the algorithm uses the standard elliptic 
curves
- `AllowedKeySizes`: A list of allowed key sizes (in bits)
- `IsPostQuantum`: If the algorithm is considered to be post quantum-safe
- `CreateKeyPair`: Method which is used to create a new private/public key pair

### Implementing the private key

```cs
public sealed class YourPrivateKey : AsymmetricPrivateKeyBase<YourPublicKey, YourPrivateKey>, IKeyExchangePrivateKey
{
	public YourPrivateKey() : base("YourAlgorithmName") { }

	public YourPrivateKey(byte[] privateKeyData) : this()
	{
		// Deserialize the key (you can store the key data in the KeyData property)
	}

	...
}
```

This example shows the definition of a private key for key exchange. If your 
algorithm is for signature, implement `ISignaturePrivateKey` instead.

You'll need to implement these abstractions:

- `Bits`: Property which returns the key size in bits
- `PublicKey`: Returns the public key instance, which needs to be disposed, if 
the private key is being disposed (set the value to `_PublicKey`)
- `IKeyExchangePrivateKey` or `ISignaturePrivateKey` abstractions

### Implementing the public key

```cs
public sealed class YourPublicKey : AsymmetricPublicKeyBase
{
	public YourPublicKey() : base("YourAlgorithmName") { }

	public YourPublicKey(byte[] privateKeyData) : this()
	{
		// Deserialize the key (you can store the key data in the KeyData property)
	}

	...
}
```

This example shows the definition of a public key for key exchange. If your 
algorithm is for signature, implement the `ISignaturePublicKey` interface.

You'll need to implement these abstractions:

- `Bits`: Property which returns the key size in bits
- `GetCopy`: Method which returns a copy of the public key instance (which 
will be disposed manual)
- `ISignaturePublicKey` abstractions, if applicable

## Best practice

- Use the core libraries algorithm implementations as examples for your own 
implementations
- Execute tests from the wan24-Crypto-Shared-Tests NuGet packet and implement 
own tests, too
- Use a custom algorithm ID >255
- Use a unique algorithm name
- Use reasonable class naems
- Create `sealed` classes
- Write documentation comment blocks for all types, constructors, fields, 
properties and methods (even the private ones) and enable XML documentation 
creation in Visual Studio
- Keep your implementations up to date (re-build for new wan24-Crypto versions)
