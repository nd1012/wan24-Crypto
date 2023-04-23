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
        /// Constructor
        /// </summary>
        public HashSha512Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override HashStreams GetHashStream(Stream? target = null, bool writable = true, CryptoOptions? options = null) => GetHashStreamInt(SHA512.Create(), target, writable, options);
    }
}
