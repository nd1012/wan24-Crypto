using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// SHA384 hash algorithm
    /// </summary>
    public sealed class HashSha384Algorithm : HashAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHA384";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 3;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 48;

        /// <summary>
        /// Constructor
        /// </summary>
        public HashSha384Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override HashAlgorithm GetHashAlgorithm(CryptoOptions? options = null) => SHA384.Create();
    }
}
