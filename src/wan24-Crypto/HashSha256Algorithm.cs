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
        /// Static constructor
        /// </summary>
        static HashSha256Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public HashSha256Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static HashSha256Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => SHA256.Create();
    }
}
