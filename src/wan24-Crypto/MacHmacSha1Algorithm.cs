﻿using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// HMAC-SHA1 MAC algorithm
    /// </summary>
    public sealed record class MacHmacSha1Algorithm : MacAlgorithmBase
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
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "HMAC SHA1";

        /// <summary>
        /// Static constructor
        /// </summary>
        static MacHmacSha1Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        private MacHmacSha1Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static MacHmacSha1Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options) => new HMACSHA1(pwd);
    }
}
