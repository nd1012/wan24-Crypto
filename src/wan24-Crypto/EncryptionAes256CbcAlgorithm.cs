using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// AES-256-CBC symmetric encryption algorithm (using ISO10126 padding)
    /// </summary>
    public sealed class EncryptionAes256CbcAlgorithm : EncryptionAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "AES256CBC";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 0;
        /// <summary>
        /// Key size in bytes
        /// </summary>
        public const int KEY_SIZE = 32;
        /// <summary>
        /// IV size in bytes
        /// </summary>
        public const int IV_SIZE = 16;
        /// <summary>
        /// Block size in bytes
        /// </summary>
        public const int BLOCK_SIZE = 16;

        /// <summary>
        /// Constructor
        /// </summary>
        public EncryptionAes256CbcAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int KeySize => KEY_SIZE;

        /// <inheritdoc/>
        public override int IvSize => IV_SIZE;

        /// <inheritdoc/>
        public override int BlockSize => BLOCK_SIZE;

        /// <inheritdoc/>
        public override bool RequireMacAuthentication => true;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <summary>
        /// Create the AES instance
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>AES instance</returns>
        public Aes CreateAes(CryptoOptions options)
        {
            options = EncryptionHelper.GetDefaultOptions(options);
            Aes res = Aes.Create();
            try
            {
                res.KeySize = KeySize << 3;
                res.Mode = CipherMode.CBC;
                res.Padding = PaddingMode.ISO10126;
                res.Key = options.Password ?? throw new ArgumentException("Missing password", nameof(options));
                return res;
            }
            catch (CryptographicException)
            {
                res.Dispose();
                throw;
            }
            catch (Exception ex)
            {
                res.Dispose();
                throw new CryptographicException(ex.Message, ex);
            }
        }

        /// <inheritdoc/>
        protected override ICryptoTransform GetEncryptor(Stream cipherData, CryptoOptions options)
        {
            using Aes aes = CreateAes(options);
            aes.IV = CreateIvBytes();
            cipherData.Write(aes.IV);
            return aes.CreateEncryptor();
        }

        /// <inheritdoc/>
        protected override async Task<ICryptoTransform> GetEncryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            using Aes aes = CreateAes(options);
            aes.IV = CreateIvBytes();
            await cipherData.WriteAsync(aes.IV, cancellationToken).DynamicContext();
            return aes.CreateEncryptor();
        }

        /// <inheritdoc/>
        protected override ICryptoTransform GetDecryptor(Stream cipherData, CryptoOptions options)
        {
            using Aes aes = CreateAes(options);
            aes.IV = ReadFixedIvBytes(cipherData, options);
            return aes.CreateDecryptor();
        }

        /// <inheritdoc/>
        protected override async Task<ICryptoTransform> GetDecryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            using Aes aes = CreateAes(options);
            aes.IV = await ReadFixedIvBytesAsync(cipherData, options, cancellationToken).DynamicContext();
            return aes.CreateDecryptor();
        }
    }
}
