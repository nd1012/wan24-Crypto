﻿using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// SHA384 hash algorithm
    /// </summary>
    public sealed record class HashSha384Algorithm : HashAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHA384";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 3;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 48;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = ALGORITHM_NAME;

        /// <summary>
        /// Static constructor
        /// </summary>
        static HashSha384Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        private HashSha384Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static HashSha384Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => SHA384.Create();
    }
}
