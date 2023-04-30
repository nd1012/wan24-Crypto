# Advanced encryption using a private PFS key

Using asymmetric keys you can enable PFS for your private encrypted data:

```cs
using IKeyExchangePrivateKey pfsKey = AsymmetricHelper.CreateKeyExchangeKeyPair();
CryptoOptions options = new CryptoOptions()
	.WithPfs(pfsKey, privateKey.PublicKey);
byte[] cipher = raw.Encrypt(pfskey, options),
	pfsPublicKeyData = (byte[])pfsKey.PublicKey.KeyData.Array.Clone();
```

`privateKey` is your stored private key, which is required to derive the key 
material from `pfsKey`. `pfsPublicKeyData` has to be managed separately in 
order to be able to derive the key material for decryption later, while the 
private `pfsKey` information should be disposed after encryption directly (and 
without storing it anywhere!):

```cs
using IAsymmetricPublicKey pfsPublicKey = ...;
CryptoOptions options = new CryptoOptions()
	.WithPfs(privateKey, pfsPublicKey);
byte[] raw = cipher.Decrypt(privateKey, options);
```
