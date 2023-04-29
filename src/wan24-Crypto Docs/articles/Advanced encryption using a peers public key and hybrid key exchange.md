# Advanced encryption using a peers public key and hybrid key exchange

Using asymmetric keys you can encrypt data in a way, that it is only 
decryptable from a peer, which gave you its public key in advance. By 
enabling hybrid cryptograhpy you can use a post quantum-safe counter 
algorithm, too, for example:

```cs
using IAsymmetricPublicKey peerPublicKey = ...;
using IAsymmetricPublicKey peerCounterPublicKey = ...;
CryptoOptions options = new CryptoOptions()
	.WithPfs(privateKey, peerPublicKey)
	.WithCounterKeyExchange(counterPrivateKey, peerCounterPublicKey);
byte[] cipher = raw.Encrypt(privateKey, options),
	publicKeyData = (byte[])privateKey.PublicKey.KeyData.Array.Clone(),
	counterPublicKeyData = (byte[])counterPrivateKey.PublicKey.KeyData.Array.Clone();
```

`privateKey` and `counterPrivateKey` are your stored private keys, which are 
required to derive the key material from `peerPublicKey` and 
`peerCounterPublicKey`.

The peer can decrypt the cipher data like this, but requires the encryptors 
`publicKeyData` and `counterPublicKeyData`:

```cs
using IAsymmetricPublicKey publicKey = ...;
using IAsymmetricPublicKey counterPublicKey = ...;
CryptoOptions options = new CryptoOptions()
	.WithPfs(peerPrivateKey, publicKey)
	.WithCounterKeyExchange(counterPeerPrivateKey, counterPublicKey);
byte[] raw = cipher.Decrypt(peerPrivateKey, options);
```
