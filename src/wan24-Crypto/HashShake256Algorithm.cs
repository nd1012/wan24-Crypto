using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// SHAKE256 hash algorithm
    /// </summary>
    public sealed record class HashShake256Algorithm : HashAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHAKE256";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 9;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 64;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "Shake256";

        /// <summary>
        /// Static constructor
        /// </summary>
        static HashShake256Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        private HashShake256Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static HashShake256Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => new NetShake256HashAlgorithmAdapter();
    }
}
