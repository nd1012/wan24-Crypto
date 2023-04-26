using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// SHA512 hash algorithm
    /// </summary>
    public sealed class HashSha512Algorithm : HashAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHA512";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 4;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 64;

        /// <summary>
        /// Static constructor
        /// </summary>
        static HashSha512Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public HashSha512Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static HashSha512Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => SHA512.Create();
    }
}
