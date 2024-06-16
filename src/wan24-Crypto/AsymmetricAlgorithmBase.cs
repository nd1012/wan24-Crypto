using System.Collections.Frozen;
using System.Security;
using System.Security.Cryptography;
using wan24.Core;
using static wan24.Core.TranslationHelper;

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
                AsymmetricKeyBits = DefaultKeySize,
                AsymmetricAlgorithmOptions = DefaultAlgorithmOptions
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
        public virtual string? DefaultAlgorithmOptions { get; }

        /// <inheritdoc/>
        public abstract AsymmetricAlgorithmUsages Usages { get; }

        /// <inheritdoc/>
        public bool CanExchangeKey => Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.KeyExchange);

        /// <inheritdoc/>
        public bool CanSign => Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.Signature);

        /// <inheritdoc/>
        public abstract bool IsEllipticCurveAlgorithm { get; }

        /// <inheritdoc/>
        public abstract bool IsPublicKeyStandardFormat { get; }

        /// <inheritdoc/>
        public abstract FrozenSet<int> AllowedKeySizes { get; }

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
        public bool IsDenied => DeniedAlgorithms.IsAsymmetricAlgorithmDenied(Value);

        /// <inheritdoc/>
        public Dictionary<int, IAsymmetricKeyPool>? KeyPool { get; set; }

        /// <inheritdoc/>
        public override IEnumerable<Status> State
        {
            get
            {
                foreach (Status status in base.State) yield return status;
                yield return new(__("Public key"), PublicKeyType, __("CLR type of the public key"));
                yield return new(__("Private key"), PrivateKeyType, __("CLR type of the private key"));
                yield return new(__("Key exchange"), CanExchangeKey, __("If the algorithm can be used for key exchange"));
                yield return new(__("Signature"), CanSign, __("If the algorithm can be used for digital signature"));
                yield return new(__("EC"), IsEllipticCurveAlgorithm, __("If the algorithm uses elliptic curves"));
                yield return new(__("Standard format"), IsPublicKeyStandardFormat, __("If the public key can be serialized in a standardized format"));
                yield return new(__("Key sizes"), string.Join(", ", AllowedKeySizes), __("The possible key sizes in bits"));
                yield return new(__("Default key size"), DefaultKeySize, __("The default key size in bits"));
                yield return new(__("Denied"), IsDenied, __("If the algorithm was denied"));
                yield return new(__("Key pools"), KeyPool is null ? false : string.Join(", ", KeyPool.Keys), __("The key sizes which offer a key pool"));
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
        public override bool EnsureAllowed(in bool throwIfDenied = true)
        {
            if (!base.EnsureAllowed(throwIfDenied)) return false;
            if (DeniedAlgorithms.IsAsymmetricAlgorithmDenied(Value))
            {
                if (!throwIfDenied) return false;
                throw CryptographicException.From(new SecurityException($"Asymmetric algorithm {DisplayName} was denied"));
            }
            return true;
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

        /// <summary>
        /// Deserialize library v1 private key data (will be removed in v3)
        /// </summary>
        /// <param name="keyData">Key data</param>
        /// <returns>Private key</returns>
        public abstract tPrivate DeserializePrivateKeyV1(byte[] keyData);//TODO Remove in v3

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

        /// <summary>
        /// Ensure an allowed elliptic curve
        /// </summary>
        /// <param name="bits">Key size in bits</param>
        /// <param name="throwIfDenied">Throw an exception, if deniedß</param>
        /// <returns>If the elliptic curve is allowed</returns>
        /// <exception cref="CryptographicException">The elliptic curve is denied</exception>
        protected virtual bool EnsureAllowedCurve(in int bits, in bool throwIfDenied = true)
        {
            if (EllipticCurves.IsCurveAllowed(bits)) return true;
            if (!throwIfDenied) return false;
            throw CryptographicException.From(new SecurityException($"Elliptic curve {EllipticCurves.GetCurveName(bits)} was denied"));
        }

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
