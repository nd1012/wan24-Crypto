# Advanced encryption using a private PFS key and hybrid key exchange

Using asymmetric keys you can enable PFS for your private encrypted data. By 
enabling hybrid cryptograhpy you can use a post quantum-safe counter 
algorithm, too, for example:

```cs
using IKeyExchangePrivateKey pfsKey = AsymmetricHelper.CreateKeyExchangeKeyPair();
using IKeyExchangePrivateKey counterPfsKey = AsymmetricHelper.CreateKeyExchangeKeyPair(HybridAlgorithmHelper.KeyExchangeAlgorithm.DefaultOptions);
CryptoOptions options = new CryptoOptions()
	.WithPfs(pfsKey, privateKey.PublicKey)
	.WithCounterKeyExchange(counterPfsKey, counterPrivateKey.PublicKey);
byte[] cipher = raw.Encrypt(pfskey, options),
	pfsPublicKeyData = (byte[])pfsKey.PublicKey.KeyData.Array.Clone(),
	counterPfsPublicKeyData = (byte[])counterPfsKey.PublicKey.KeyData.Array.Clone();
```

`privateKey` and `counterPrivateKey` are your stored private keys, which are 
required to derive the key material from `pfsKey` and `counterPfsKey`. 
`pfsPublicKeyData` and `counterPfsPublicKeyData` has to be managed separately 
in order to be able to derive the key material for decryption later, while the 
private `pfsKey` and `counterPfsKey` informations should be disposed after 
encryption directly (and without storing it anywhere!):

```cs
using IAsymmetricPublicKey pfsPublicKey = ...;
using IAsymmetricPublicKey counterPfsPublicKey = ...;
CryptoOptions options = new CryptoOptions()
	.WithPfs(privateKey, pfsPublicKey)
	.WithCounterKeyExchange(counterPrivateKey, counterPfsPublicKey);
byte[] raw = cipher.Decrypt(privateKey, options);
```
