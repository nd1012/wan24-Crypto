using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// MD5 hash algorithm
    /// </summary>
    public sealed class HashMd5Algorithm : HashAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "MD5";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 0;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 16;

        /// <summary>
        /// Constructor
        /// </summary>
        public HashMd5Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override HashStreams GetHashStream(Stream? target = null, bool writable = true, CryptoOptions? options = null) => GetHashStreamInt(MD5.Create(), target, writable, options);
    }
}
