namespace wan24.Crypto
{
    /// <summary>
    /// Encryption extensions
    /// </summary>
    public static class EncryptionExtensions
    {
        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this ReadOnlySpan<byte> rawData, byte[] pwd, CryptoOptions? options = null)
        {
            try
            {
                using MemoryStream ms = new();
                ms.Write(rawData);
                ms.Position = 0;
                using MemoryStream cipherData = new();
                ms.Encrypt(cipherData, pwd, options);
                return cipherData.ToArray();
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this Span<byte> rawData, byte[] pwd, CryptoOptions? options = null)
            => Encrypt((ReadOnlySpan<byte>)rawData, pwd, options);

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this ReadOnlyMemory<byte> rawData, byte[] pwd, CryptoOptions? options = null)
            => rawData.Span.Encrypt(pwd, options);

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this Memory<byte> rawData, byte[] pwd, CryptoOptions? options = null)
            => rawData.Span.Encrypt(pwd, options);

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this byte[] rawData, byte[] pwd, CryptoOptions? options = null)
            => rawData.AsSpan().Encrypt(pwd, options);

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this ReadOnlySpan<byte> rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
        {
            try
            {
                using MemoryStream ms = new();
                ms.Write(rawData);
                ms.Position = 0;
                using MemoryStream cipherData = new();
                ms.Encrypt(cipherData, key, options);
                return cipherData.ToArray();
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this Span<byte> rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
            => Encrypt((ReadOnlySpan<byte>)rawData, key, options);

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this ReadOnlyMemory<byte> rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
            => rawData.Span.Encrypt(key, options);

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this Memory<byte> rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
            => rawData.Span.Encrypt(key, options);

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] Encrypt(this byte[] rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
            => rawData.AsSpan().Encrypt(key, options);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this ReadOnlySpan<byte> cipherData, byte[] pwd, CryptoOptions? options = null)
        {
            try
            {
                using MemoryStream ms = new();
                ms.Write(cipherData);
                ms.Position = 0;
                using MemoryStream rawData = new();
                ms.Decrypt(rawData, pwd, options);
                return rawData.ToArray();
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this Span<byte> cipherData, byte[] pwd, CryptoOptions? options = null)
            => Decrypt((ReadOnlySpan<byte>)cipherData, pwd, options);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this Memory<byte> cipherData, byte[] pwd, CryptoOptions? options = null)
            => cipherData.Span.Decrypt(pwd, options);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this ReadOnlyMemory<byte> cipherData, byte[] pwd, CryptoOptions? options = null)
            => cipherData.Span.Decrypt(pwd, options);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this byte[] cipherData, byte[] pwd, CryptoOptions? options = null)
            => cipherData.AsSpan().Decrypt(pwd, options);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this ReadOnlySpan<byte> cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
        {
            try
            {
                using MemoryStream ms = new();
                ms.Write(cipherData);
                ms.Position = 0;
                using MemoryStream rawData = new();
                ms.Decrypt(rawData, key, options);
                return rawData.ToArray();
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this Span<byte> cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
            => Decrypt((ReadOnlySpan<byte>)cipherData, key, options);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this ReadOnlyMemory<byte> cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
            => cipherData.Span.Decrypt(key, options);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this Memory<byte> cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
            => cipherData.Span.Decrypt(key, options);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static byte[] Decrypt(this byte[] cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
            => cipherData.AsSpan().Decrypt(key, options);
    }
}
