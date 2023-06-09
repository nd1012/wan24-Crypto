﻿using System.Collections.ObjectModel;
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
        public CryptoOptions DefaultOptions
        {
            get
            {
                CryptoOptions res = _DefaultOptions.Clone();
                res.AsymmetricAlgorithm = Name;
                res.AsymmetricKeyBits = DefaultKeySize;
                return res;
            }
        }

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
        public abstract tPrivate CreateKeyPair(CryptoOptions? options = null);

        /// <inheritdoc/>
        public tPublic DeserializePublicKey(byte[] keyData)
        {
            try
            {
                return Activator.CreateInstance(typeof(tPublic), new object?[] { keyData }) as tPublic ?? throw new InvalidProgramException($"Failed to instance {typeof(tPublic)}");
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
                return Activator.CreateInstance(typeof(tPrivate), new object?[] { keyData }) as tPrivate ?? throw new InvalidProgramException($"Failed to instance {typeof(tPrivate)}");
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
                options ??= DefaultOptions;
                if (CanExchangeKey) options = AsymmetricHelper.GetDefaultKeyExchangeOptions(options);
                if (CanSign) options = AsymmetricHelper.GetDefaultSignatureOptions(options);
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
        IAsymmetricPrivateKey IAsymmetricAlgorithm.CreateKeyPair(CryptoOptions? options) => CreateKeyPair(options);

        /// <inheritdoc/>
        IAsymmetricPublicKey IAsymmetricAlgorithm.DeserializePublicKey(byte[] keyData) => DeserializePublicKey(keyData);

        /// <inheritdoc/>
        IAsymmetricPrivateKey IAsymmetricAlgorithm.DeserializePrivateKey(byte[] keyData) => DeserializePrivateKey(keyData);
    }
}
