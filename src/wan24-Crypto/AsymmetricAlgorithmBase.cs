using System.Collections.ObjectModel;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for an asymmetric algorithm
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tPrivate">Private key type</typeparam>
    public abstract record class AsymmetricAlgorithmBase<tPublic, tPrivate> : CryptoAlgorithmBase, IAsymmetricAlgorithm
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

        /// <summary>
        /// Private key type
        /// </summary>
        public static Type PrivateKeyType { get; } = typeof(tPrivate);

        /// <summary>
        /// Public key type
        /// </summary>
        public static Type PublicKeyType { get; } = typeof(tPublic);

        /// <inheritdoc/>
        public CryptoOptions DefaultOptions
        {
            get
            {
                CryptoOptions res = _DefaultOptions.GetCopy();
                if (CanSign) AsymmetricHelper.GetDefaultSignatureOptions(res);
                if (CanExchangeKey) AsymmetricHelper.GetDefaultKeyExchangeOptions(res);
                return res;
            }
        }

        /// <inheritdoc/>
        public abstract AsymmetricAlgorithmUsages Usages { get; }

        /// <inheritdoc/>
        public bool CanExchangeKey => Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.KeyExchange);

        /// <inheritdoc/>
        public bool CanSign => Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.Signature);

        /// <inheritdoc/>
        public abstract bool IsEllipticCurveAlgorithm { get; }

        /// <inheritdoc/>
        public abstract ReadOnlyCollection<int> AllowedKeySizes { get; }

        /// <inheritdoc/>
        Type IAsymmetricAlgorithm.PrivateKeyType => PrivateKeyType;

        /// <inheritdoc/>
        Type IAsymmetricAlgorithm.PublicKeyType => PublicKeyType;

        /// <inheritdoc/>
        public int DefaultKeySize
        {
            get => _DefaultKeySize;
            set
            {
                try
                {
                    if (!value.In(AllowedKeySizes)) throw new ArgumentOutOfRangeException(nameof(value));
                    _DefaultKeySize = value;
                }
                catch(Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
            }
        }

        /// <inheritdoc/>
        public virtual CryptoOptions EnsureDefaultOptions(CryptoOptions? options = null)
        {
            if (options is null) return DefaultOptions;
            options.AsymmetricAlgorithm = _DefaultOptions.AsymmetricAlgorithm;
            options.AsymmetricKeyBits = _DefaultOptions.AsymmetricKeyBits;
            if (CanSign && options.HashAlgorithm is null) HashHelper.GetDefaultOptions(options);
            return options;
        }

        /// <inheritdoc/>
        public abstract tPrivate CreateKeyPair(CryptoOptions? options = null);

        /// <inheritdoc/>
        public virtual Task<tPrivate> CreateKeyPairAsync(CryptoOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(CreateKeyPair(options));

        /// <inheritdoc/>
        public tPublic DeserializePublicKey(byte[] keyData)
        {
            try
            {
                return Activator.CreateInstance(typeof(tPublic), [keyData]) as tPublic ?? throw new InvalidProgramException($"Failed to instance {typeof(tPublic)}");
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public tPrivate DeserializePrivateKey(byte[] keyData)
        {
            try
            {
                return Activator.CreateInstance(typeof(tPrivate), [keyData]) as tPrivate ?? throw new InvalidProgramException($"Failed to instance {typeof(tPrivate)}");
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public virtual byte[] DeriveKey(byte[] keyExchangeData, CryptoOptions? options = null)
        {
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                options = options?.GetCopy() ?? DefaultOptions;
                using IKeyExchangePrivateKey key = (CreateKeyPair(options) as IKeyExchangePrivateKey)!;
                return key.DeriveKey(keyExchangeData);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public virtual bool CanHandleNetAlgorithm(AsymmetricAlgorithm algo) => false;

        /// <inheritdoc/>
        IAsymmetricPrivateKey IAsymmetricAlgorithm.CreateKeyPair(CryptoOptions? options) => CreateKeyPair(options);

        async Task<IAsymmetricPrivateKey> IAsymmetricAlgorithm.CreateKeyPairAsync(CryptoOptions? options, CancellationToken cancellationToken)
            => await CreateKeyPairAsync(options, cancellationToken).DynamicContext();

        /// <inheritdoc/>
        IAsymmetricPublicKey IAsymmetricAlgorithm.DeserializePublicKey(byte[] keyData) => DeserializePublicKey(keyData);

        /// <inheritdoc/>
        IAsymmetricPrivateKey IAsymmetricAlgorithm.DeserializePrivateKey(byte[] keyData) => DeserializePrivateKey(keyData);
    }
}
