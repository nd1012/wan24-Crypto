﻿using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// SHA256 hash algorithm
    /// </summary>
    public sealed record class HashSha256Algorithm : HashAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHA256";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 2;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 32;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = ALGORITHM_NAME;

        /// <summary>
        /// Static constructor
        /// </summary>
        static HashSha256Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        private HashSha256Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static HashSha256Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => SHA256.Create();
    }
}
