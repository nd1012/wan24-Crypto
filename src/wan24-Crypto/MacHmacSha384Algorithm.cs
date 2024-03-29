﻿using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// HMAC-SHA384 MAC algorithm
    /// </summary>
    public sealed record class MacHmacSha384Algorithm : MacAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "HMAC-SHA384";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 2;
        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public const int MAC_LENGTH = 48;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "HMAC SHA384";

        /// <summary>
        /// Static constructor
        /// </summary>
        static MacHmacSha384Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        private MacHmacSha384Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static MacHmacSha384Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options) => new HMACSHA384(pwd);
    }
}
