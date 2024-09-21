using System.Collections.Frozen;
using System.Security;

namespace wan24.Crypto
{
    /// <summary>
    /// Asymmetric void algorithm (used in case there's no asymmetric algorithm available)
    /// </summary>
    public sealed record class AsymmetricVoidAlgorithm : AsymmetricAlgorithmBase<AsymmetricVoidPublicKey, AsymmetricVoidPrivateKey>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "VOID";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = -1;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.KeyExchange | AsymmetricAlgorithmUsages.Signature;

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes = Array.Empty<int>().ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricVoidAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static AsymmetricVoidAlgorithm Instance { get; } = new();

        /// <inheritdoc/>
        public override AsymmetricAlgorithmUsages Usages => USAGES;

        /// <inheritdoc/>
        public override bool IsEllipticCurveAlgorithm => false;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => false;

        /// <inheritdoc/>
        public override FrozenSet<int> AllowedKeySizes => _AllowedKeySizes;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override bool IsSupported => false;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => 0;

        /// <inheritdoc/>
        public override AsymmetricVoidPrivateKey CreateKeyPair(CryptoOptions? options = null) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override AsymmetricVoidPrivateKey DeserializePrivateKeyV1(byte[] keyData) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override bool EnsureAllowed(in bool throwIfDenied = true)
        {
            if (!throwIfDenied) return false;
            throw CryptographicException.From(new SecurityException("The VIOD algorithm can't be used"));
        }
    }
}
