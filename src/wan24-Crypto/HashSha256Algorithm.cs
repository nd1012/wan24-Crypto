using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// SHA256 hash algorithm
    /// </summary>
    public sealed class HashSha256Algorithm : HashAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHA256";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 2;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 32;

        /// <summary>
        /// Constructor
        /// </summary>
        public HashSha256Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override HashAlgorithm GetHashAlgorithm(CryptoOptions? options = null) => SHA256.Create();
    }
}
