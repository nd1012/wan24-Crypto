using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// SHA1 hash algorithm
    /// </summary>
    public sealed class HashSha1Algorithm : HashAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHA1";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 0;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 20;

        /// <summary>
        /// Static constructor
        /// </summary>
        static HashSha1Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public HashSha1Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static HashSha1Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => SHA1.Create();
    }
}
