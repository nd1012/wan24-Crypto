using System.Collections.ObjectModel;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for an asymmetric algorithm
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tPrivate">Private key type</typeparam>
    public abstract class AsymmetricAlgorithmBase<tPublic, tPrivate> : CryptoAlgorithmBase, IAsymmetricAlgorithm
        where tPublic : AsymmetricPublicKeyBase, IAsymmetricPublicKey, new()
        where tPrivate : AsymmetricPrivateKeyBase<tPublic, tPrivate>, IAsymmetricPrivateKey, new()
    {
        /// <summary>
        /// Default key size
        /// </summary>
        protected int _DefaultKeySize = 0;
        /// <summary>
        /// Default options
        /// </summary>
        protected CryptoOptions _DefaultOptions;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        protected AsymmetricAlgorithmBase(string name, int value) : base(name, value)
            => _DefaultOptions = new()
            {
                AsymmetricAlgorithm = name,
                AsymmetricKeyBits = DefaultKeySize
            };

        /// <inheritdoc/>
        public CryptoOptions DefaultOptions => _DefaultOptions.Clone();

        /// <inheritdoc/>
        public abstract AsymmetricAlgorithmUsages Usages { get; }

        /// <inheritdoc/>
        public bool CanExchangeKey => Usages.HasFlag(AsymmetricAlgorithmUsages.KeyExchange);

        /// <inheritdoc/>
        public bool CanSign => Usages.HasFlag(AsymmetricAlgorithmUsages.Signature);

        /// <inheritdoc/>
        public abstract bool IsEllipticCurveAlgorithm { get; }

        /// <inheritdoc/>
        public abstract ReadOnlyCollection<int> AllowedKeySizes { get; }

        /// <inheritdoc/>
        public int DefaultKeySize
        {
            get => _DefaultKeySize;
            set
            {
                if (!value.In(AllowedKeySizes)) throw new ArgumentOutOfRangeException(nameof(value));
                _DefaultKeySize = value;
            }
        }

        /// <inheritdoc/>
        public abstract tPrivate CreateKeyPair(CryptoOptions? options = null);

        /// <inheritdoc/>
        public tPublic DeserializePublicKey(byte[] keyData)
            => Activator.CreateInstance(typeof(tPublic), new object?[] { keyData }) as tPublic ?? throw new InvalidProgramException($"Failed to instance {typeof(tPublic)}");

        /// <inheritdoc/>
        public tPrivate DeserializePrivateKey(byte[] keyData)
            => Activator.CreateInstance(typeof(tPrivate), new object?[] { keyData }) as tPrivate ?? throw new InvalidProgramException($"Failed to instance {typeof(tPrivate)}");

        /// <inheritdoc/>
        public virtual byte[] DeriveKey(byte[] keyExchangeData, CryptoOptions? options = null)
        {
            using IKeyExchangePrivateKey key = (CreateKeyPair(options) as IKeyExchangePrivateKey)!;
            return key.DeriveKey(keyExchangeData);
        }

        /// <inheritdoc/>
        IAsymmetricPrivateKey IAsymmetricAlgorithm.CreateKeyPair(CryptoOptions? options) => CreateKeyPair(options);

        /// <inheritdoc/>
        IAsymmetricPublicKey IAsymmetricAlgorithm.DeserializePublicKey(byte[] keyData) => DeserializePublicKey(keyData);

        /// <inheritdoc/>
        IAsymmetricPrivateKey IAsymmetricAlgorithm.DeserializePrivateKey(byte[] keyData) => DeserializePrivateKey(keyData);
    }
}
