using System.Security.Cryptography;

namespace wan24.Crypto
{
    // Abstractions
    public partial class EncryptionAlgorithmBase
    {
        /// <summary>
        /// Key size in bytes
        /// </summary>
        public abstract int KeySize { get; }

        /// <summary>
        /// IV size in bytes
        /// </summary>
        public abstract int IvSize { get; }

        /// <summary>
        /// Block size in bytes
        /// </summary>
        public abstract int BlockSize { get; }

        /// <summary>
        /// Is a MAC authentication required?
        /// </summary>
        public abstract bool RequireMacAuthentication { get; }

        /// <summary>
        /// Get the encryptor (need to write the information (IV bytes etc.) which is required to create a decryptor)
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <returns>Transform</returns>
        protected abstract ICryptoTransform GetEncryptor(Stream cipherData, CryptoOptions options);

        /// <summary>
        /// Get the encryptor (need to write the information (IV bytes etc.) which is required to create a decryptor)
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Transform</returns>
        protected abstract Task<ICryptoTransform> GetEncryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken);

        /// <summary>
        /// Get the decryptor
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <returns>Transform</returns>
        protected abstract ICryptoTransform GetDecryptor(Stream cipherData, CryptoOptions options);

        /// <summary>
        /// Get the decryptor
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Transform</returns>
        protected abstract Task<ICryptoTransform> GetDecryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken);
    }
}
