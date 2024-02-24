using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// HMAC-SHA3-512 MAC algorithm
    /// </summary>
    public sealed record class MacHmacSha3_512Algorithm : MacAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "HMAC-SHA3-512";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 6;
        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public const int MAC_LENGTH = 64;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "HMAC SHA3-512";

        /// <summary>
        /// Static constructor
        /// </summary>
        static MacHmacSha3_512Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        private MacHmacSha3_512Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static MacHmacSha3_512Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options) => new HMACSHA3_512(pwd);
    }
}
