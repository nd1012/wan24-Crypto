﻿using System.Collections.ObjectModel;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// EC Diffie Hellman asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricEcDiffieHellmanAlgorithm : AsymmetricAlgorithmBase<AsymmetricEcDiffieHellmanPublicKey, AsymmetricEcDiffieHellmanPrivateKey>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "ECDH";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 0;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 521;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.KeyExchange;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "EC Diffie Hellman";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly ReadOnlyCollection<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricEcDiffieHellmanAlgorithm()
        {
            _AllowedKeySizes = new List<int>()
            {
                256,
                384,
                521
            }.AsReadOnly();
            Instance = new();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEcDiffieHellmanAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) => _DefaultOptions.AsymmetricKeyBits = DefaultKeySize = DEFAULT_KEY_SIZE;

        /// <summary>
        /// Instance
        /// </summary>
        public static AsymmetricEcDiffieHellmanAlgorithm Instance { get; }

        /// <inheritdoc/>
        public override AsymmetricAlgorithmUsages Usages => USAGES;

        /// <inheritdoc/>
        public override bool IsEllipticCurveAlgorithm => true;

        /// <inheritdoc/>
        public override ReadOnlyCollection<int> AllowedKeySizes => _AllowedKeySizes;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override AsymmetricEcDiffieHellmanPrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                options ??= DefaultOptions;
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                return new(ECDiffieHellman.Create(EllipticCurves.GetCurve(options.AsymmetricKeyBits)));
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override bool CanHandleNetAlgorithm(AsymmetricAlgorithm algo) => typeof(ECDiffieHellman).IsAssignableFrom(algo.GetType());
    }
}
