using System.Collections.Frozen;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// EC DSA asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricEcDsaAlgorithm : AsymmetricAlgorithmBase<AsymmetricEcDsaPublicKey, AsymmetricEcDsaPrivateKey>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "ECDSA";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 1;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 521;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.Signature;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "EC DSA";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricEcDsaAlgorithm()
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
        private AsymmetricEcDsaAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) => _DefaultOptions.AsymmetricKeyBits = DefaultKeySize = DEFAULT_KEY_SIZE;

        /// <summary>
        /// Instance
        /// </summary>
        public static AsymmetricEcDsaAlgorithm Instance { get; }

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
        public override AsymmetricEcDsaPrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options ??= DefaultOptions;
                EnsureAllowedCurve(options.AsymmetricKeyBits);
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                return new(ECDsa.Create(EllipticCurves.GetCurve(options.AsymmetricKeyBits)));
            }
            catch(CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override bool CanHandleNetAlgorithm(AsymmetricAlgorithm algo) => typeof(ECDsa).IsAssignableFrom(algo.GetType());

        /// <inheritdoc/>
        public override AsymmetricEcDsaPrivateKey DeserializePrivateKeyV1(byte[] keyData)
        {
            ECDsa dsa = ECDsa.Create();
            try
            {
                dsa.ImportECPrivateKey(keyData, out int red);
                if (red != keyData.Length) throw new InvalidDataException("The key data wasn't fully used");
                return new(dsa);
            }
            catch (Exception ex)
            {
                dsa.Dispose();
                throw CryptographicException.From(ex);
            }
        }
    }
}
