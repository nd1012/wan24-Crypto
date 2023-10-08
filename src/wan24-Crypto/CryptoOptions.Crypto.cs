using wan24.Core;

namespace wan24.Crypto
{
    // Crypto
    public partial record class CryptoOptions
    {
        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <returns>Cipher data</returns>
        public byte[] Encrypt(ReadOnlySpan<byte> rawData)
        {
            if (PrivateKey?.Algorithm.CanExchangeKey ?? false) return rawData.Encrypt(PrivateKey, this);
            Password ??= RND.GetBytes(64);
            return rawData.Encrypt(Password, this);
        }

        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <returns>Cipher data</returns>
        public byte[] Encrypt(Span<byte> rawData) => Encrypt((ReadOnlySpan<byte>)rawData);

        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        public void Encrypt(Stream rawData, Stream cipherData)
        {
            if (PrivateKey?.Algorithm.CanExchangeKey ?? false)
            {
                rawData.Encrypt(cipherData, PrivateKey, this);
                return;
            }
            Password ??= RND.GetBytes(64);
            rawData.Encrypt(cipherData, Password, this);
        }

        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task EncryptAsync(Stream rawData, Stream cipherData, CancellationToken cancellationToken = default)
        {
            if (PrivateKey?.Algorithm.CanExchangeKey ?? false)
            {
                await rawData.EncryptAsync(cipherData, PrivateKey, this, cancellationToken).DynamicContext();
                return;
            }
            Password ??= await RND.GetBytesAsync(64).DynamicContext();
            await rawData.EncryptAsync(cipherData, Password, this, cancellationToken: cancellationToken).DynamicContext();
        }
        /// <summary>
        /// Decrypt data
        /// </summary>
        /// <param name="cipherData">Raw data</param>
        /// <returns>Cipher data</returns>
        public byte[] Decrypt(ReadOnlySpan<byte> cipherData)
        {
            if (PrivateKey?.Algorithm.CanExchangeKey ?? false) return cipherData.Decrypt(PrivateKey, this);
            if (Password is null) throw new InvalidOperationException("No password, no private key");
            return cipherData.Decrypt(Password, this);
        }

        /// <summary>
        /// Decrypt data
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <returns>Cipher data</returns>
        public byte[] Decrypt(Span<byte> rawData) => Decrypt((ReadOnlySpan<byte>)rawData);

        /// <summary>
        /// Decrypt data
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        public void Decrypt(Stream cipherData, Stream rawData)
        {
            if (PrivateKey?.Algorithm.CanExchangeKey ?? false)
            {
                cipherData.Decrypt(rawData, PrivateKey, this);
                return;
            }
            if (Password is null) throw new InvalidOperationException("No password, no private key");
            cipherData.Decrypt(rawData, Password, this);
        }

        /// <summary>
        /// Decrypt data
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task DecryptAsync(Stream cipherData, Stream rawData, CancellationToken cancellationToken = default)
        {
            if (PrivateKey?.Algorithm.CanExchangeKey ?? false)
            {
                await cipherData.DecryptAsync(rawData, PrivateKey, this, cancellationToken).DynamicContext();
                return;
            }
            if (Password is null) throw new InvalidOperationException("No password, no private key");
            await cipherData.DecryptAsync(rawData, Password, this, cancellationToken: cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <returns>This</returns>
        public CryptoOptions CreateMac(ReadOnlySpan<byte> data)
        {
            Password ??= RND.GetBytes(64);
            Mac = data.Mac(Password, this);
            if (UsingCounterMac) HybridAlgorithmHelper.ComputeMac(this);
            return this;
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <returns>This</returns>
        public CryptoOptions CreateMac(Span<byte> data) => CreateMac((ReadOnlySpan<byte>)data);

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <returns>This</returns>
        public CryptoOptions CreateMac(Stream data)
        {
            Password ??= RND.GetBytes(64);
            Mac = data.Mac(Password, this);
            if (UsingCounterMac) HybridAlgorithmHelper.ComputeMac(this);
            return this;
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>This</returns>
        public async Task CreateMacAsync(Stream data, CancellationToken cancellationToken = default)
        {
            Password ??= await RND.GetBytesAsync(64).DynamicContext();
            Mac = await data.MacAsync(Password, this, cancellationToken).DynamicContext();
            if (UsingCounterMac) HybridAlgorithmHelper.ComputeMac(this);
        }

        /// <summary>
        /// Stretch the password
        /// </summary>
        /// <param name="len">Stretched password length in bytes</param>
        /// <returns>This</returns>
        public CryptoOptions StretchKey(int len)
        {
            Password ??= RND.GetBytes(64);
            (Password, KdfSalt) = Password.Stretch(len, options: this);
            if (UsingCounterKdf) HybridAlgorithmHelper.StretchPassword(this);
            return this;
        }
    }
}
