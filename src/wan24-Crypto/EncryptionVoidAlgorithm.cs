using System.Security;
using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// Symmetric void encryption algorithm (used when there's no algorithm available)
    /// </summary>
    public sealed record class EncryptionVoidAlgorithm : EncryptionAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "VOID";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = -1;

        /// <summary>
        /// Constructor
        /// </summary>
        private EncryptionVoidAlgorithm():base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static EncryptionVoidAlgorithm Instance { get; } = new();

        /// <inheritdoc/>
        public override int KeySize => 0;

        /// <inheritdoc/>
        public override int IvSize => 0;

        /// <inheritdoc/>
        public override int BlockSize => 0;

        /// <inheritdoc/>
        public override bool RequireMacAuthentication => false;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override bool IsSupported => false;

        /// <inheritdoc/>
        public override byte[] EnsureValidKeyLength(byte[] key) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override bool IsKeyLengthValid(int len) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override bool EnsureAllowed(in bool throwIfDenied = true)
        {
            if (!throwIfDenied) return false;
            throw CryptographicException.From(new SecurityException("The VIOD algorithm can't be used"));
        }

        /// <inheritdoc/>
        protected override ICryptoTransform GetDecryptor(Stream cipherData, CryptoOptions options) => throw new NotSupportedException();

        /// <inheritdoc/>
        protected override Task<ICryptoTransform> GetDecryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken) => throw new NotSupportedException();

        /// <inheritdoc/>
        protected override ICryptoTransform GetEncryptor(Stream cipherData, CryptoOptions options) => throw new NotSupportedException();

        /// <inheritdoc/>
        protected override Task<ICryptoTransform> GetEncryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
