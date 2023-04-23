using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// HMAC-SHA1 MAC algorithm
    /// </summary>
    public sealed class MacHmacSha1Algorithm : MacAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "HMAC-SHA1";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 0;
        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public const int MAC_LENGTH = 20;

        /// <summary>
        /// Constructor
        /// </summary>
        public MacHmacSha1Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override MacStreams GetMacStream(byte[] pwd, Stream? target = null, bool writable = true, CryptoOptions? options = null)
            => GetMacStreamInt(new HMACSHA1(pwd), target, writable, options);
    }
}
