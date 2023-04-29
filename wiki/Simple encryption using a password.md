# Simple encryption using a password

The most simple encryption uses a symmetric password. Here are some examples 
(using all the default settings):

```cs
// In memory
byte[] cipher = raw.Encrypt(password);
raw = cipher.Decrypt(password);

// Streams
rawStream.Encrypt(cipherStream, password);
cipherStream.Position = 0;
rawStream.Setlength(0);
cipherStream.Decrypt(rawStream, password);
```

There extensions for `byte[]`, `Span<byte>`, `Memory<byte>` and `Stream`. The 
used password is not restricted at all: KDF will be used to match the key 
length which may be required by the cipher algorithm (if 
`CryptoOptions.KdfIncluded` is `true`!).

The IV bytes will be auto-generated and prepended to the cipher data - and 
also be red from the cipher data, when decrypting, so that you don't have to 
care about that at all.

If a cipher requires MAC authentication (like AES256-CBC), an automatically 
managed MAC will authenticate the IV bytes, too.
