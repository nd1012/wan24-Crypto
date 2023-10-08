using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// HMAC-SHA256 MAC algorithm
    /// </summary>
    public sealed record class MacHmacSha256Algorithm : MacAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "HMAC-SHA256";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 1;
        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public const int MAC_LENGTH = 32;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "HMAC SHA256";

        /// <summary>
        /// Static constructor
        /// </summary>
        static MacHmacSha256Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public MacHmacSha256Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static MacHmacSha256Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options) => new HMACSHA256(pwd);
    }
}
