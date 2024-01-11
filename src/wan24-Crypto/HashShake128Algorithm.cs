using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// SHAKE128 hash algorithm
    /// </summary>
    public sealed record class HashShake128Algorithm : HashAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHAKE128";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 8;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 32;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "Shake128";

        /// <summary>
        /// Static constructor
        /// </summary>
        static HashShake128Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public HashShake128Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static HashShake128Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => new NetShake128HashAlgorithmAdapter();
    }
}
