using System.Collections.Frozen;
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
        /// Maximum key usage count
        /// </summary>
        public const long MAX_KEY_USAGE_COUNT = long.MaxValue;
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
        private static readonly FrozenSet<int> _AllowedKeySizes;

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
            }.ToFrozenSet();
            Instance = new();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricEcDiffieHellmanAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) => _DefaultOptions.AsymmetricKeyBits = DefaultKeySize = DEFAULT_KEY_SIZE;

        /// <summary>
        /// Instance
        /// </summary>
        public static AsymmetricEcDiffieHellmanAlgorithm Instance { get; }

        /// <inheritdoc/>
        public override AsymmetricAlgorithmUsages Usages => USAGES;

        /// <inheritdoc/>
        public override bool IsEllipticCurveAlgorithm => true;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        public override FrozenSet<int> AllowedKeySizes => _AllowedKeySizes;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override bool IsSupported => !ENV.IsBrowserApp;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        public override AsymmetricEcDiffieHellmanPrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options ??= DefaultOptions;
                EnsureAllowedCurve(options.AsymmetricKeyBits);
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

        /// <inheritdoc/>
        public override AsymmetricEcDiffieHellmanPrivateKey DeserializePrivateKeyV1(byte[] keyData)
        {
            ECDiffieHellman ecdh = ECDiffieHellman.Create();
            try
            {
                ecdh.ImportECPrivateKey(keyData, out int red);
                if (red != keyData.Length) throw new InvalidDataException("The key data wasn't fully used");
                return new(ecdh);
            }
            catch (Exception ex)
            {
                ecdh.Dispose();
                throw CryptographicException.From(ex);
            }
        }
    }
}
