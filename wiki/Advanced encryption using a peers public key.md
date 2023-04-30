# Advanced encryption using a peers public key

Using asymmetric keys you can encrypt data in a way, that it is only 
decryptable from a peer, which gave you its public key in advance:

```cs
using IAsymmetricPublicKey peerPublicKey = ...;
CryptoOptions options = new CryptoOptions()
	.WithPfs(privateKey, peerPublicKey);
byte[] cipher = raw.Encrypt(privateKey, options),
	publicKeyData = (byte[])privateKey.PublicKey.KeyData.Array.Clone();
```

`privateKey` is your stored private key, which is required to derive the key 
material from `peerPublicKey` for encryption.

The peer can decrypt the cipher data like this, but requires the encryptors 
`publicKeyData`:

```cs
using IAsymmetricPublicKey publicKey = ...;
CryptoOptions options = new CryptoOptions()
	.WithPfs(peerPrivateKey, publicKey);
byte[] raw = cipher.Decrypt(privateKey, options);
```
