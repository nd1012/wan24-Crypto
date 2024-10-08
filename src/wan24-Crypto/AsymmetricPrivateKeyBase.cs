﻿using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for an asymmetric private key
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tPrivate">Private key type</typeparam>
    public abstract record class AsymmetricPrivateKeyBase<tPublic, tPrivate> : AsymmetricKeyBase, IAsymmetricPrivateKey
        where tPublic : AsymmetricPublicKeyBase, IAsymmetricPublicKey, new()
        where tPrivate: AsymmetricPrivateKeyBase<tPublic, tPrivate>, IAsymmetricPrivateKey, new()
    {
        /// <summary>
        /// Public key
        /// </summary>
        protected tPublic? _PublicKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected AsymmetricPrivateKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Public key (don't dispose - the instance will be disposed if the private key instance is being disposed!)
        /// </summary>
        public abstract tPublic PublicKey { get; }

        /// <inheritdoc/>
        public override byte[] ID => PublicKey.ID.CloneArray();

        /// <inheritdoc/>
        IAsymmetricPublicKey IAsymmetricPrivateKey.PublicKey => PublicKey;

        /// <inheritdoc/>
        public IAsymmetricPrivateKey GetCopy()
        {
            try
            {
                return Activator.CreateInstance(typeof(tPrivate), [KeyData.Array.CloneArray()]) as tPrivate ?? throw new InvalidProgramException($"Failed to copy {typeof(tPrivate)}");
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public virtual SignatureContainer SignData(byte[] data, string? purpose = null, CryptoOptions? options = null)
        {
            try
            {
                EnsureUndisposed();
                Algorithm.EnsureAllowed();
                EnsureAllowedCurve();
                if (!Algorithm.CanSign) throw new NotSupportedException("This asymmetric algorithm doesn't support signature");
                options ??= Algorithm.DefaultOptions;
                options = AsymmetricHelper.GetDefaultSignatureOptions(options);
                return SignHash(data.Hash(options), purpose, options);
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
        public virtual SignatureContainer SignData(Stream data, string? purpose = null, CryptoOptions? options = null)
        {
            try
            {
                EnsureUndisposed();
                Algorithm.EnsureAllowed();
                EnsureAllowedCurve();
                if (!Algorithm.CanSign) throw new NotSupportedException("This asymmetric algorithm doesn't support signature");
                options ??= Algorithm.DefaultOptions;
                options = AsymmetricHelper.GetDefaultSignatureOptions(options);
                return SignHash(data.Hash(options), purpose, options);
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
        public virtual async Task<SignatureContainer> SignDataAsync(Stream data, string? purpose = null, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            try
            {
                EnsureUndisposed();
                Algorithm.EnsureAllowed();
                EnsureAllowedCurve();
                if (!Algorithm.CanSign) throw new NotSupportedException("This asymmetric algorithm doesn't support signature");
                options ??= Algorithm.DefaultOptions;
                options = AsymmetricHelper.GetDefaultSignatureOptions(options);
                return SignHash(await data.HashAsync(options, cancellationToken).DynamicContext(), purpose, options);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw await CryptographicException.FromAsync(ex);
            }
        }

        /// <inheritdoc/>
        public virtual SignatureContainer SignHash(byte[] hash, string? purpose = null, CryptoOptions? options = null)
        {
            try
            {
                EnsureUndisposed();
                Algorithm.EnsureAllowed();
                EnsureAllowedCurve();
                if (!Algorithm.CanSign) throw new NotSupportedException("This asymmetric algorithm doesn't support signature");
                options ??= Algorithm.DefaultOptions;
                options = AsymmetricHelper.GetDefaultSignatureOptions(options);
                options.KeySuite?.CountAsymmetricKeyUsage(this);
                SignatureContainer res = new(options.HashAlgorithm!, hash, (ISignaturePrivateKey)this, options.CounterPrivateKey as ISignaturePrivateKey, purpose);
                res.Signature = SignHashRaw(res.CreateSignatureHash());
                if (options.CounterPrivateKey is ISignaturePrivateKey) HybridAlgorithmHelper.Sign(res, options);
                PublicKey.ValidateSignature(res);
                return res;
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
        public virtual byte[] SignHashRaw(byte[] hash) => throw new NotSupportedException();

        /// <inheritdoc/>
        public virtual (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData(IAsymmetricPublicKey? publicKey = null, CryptoOptions? options = null)
            => throw new NotSupportedException();


        /// <inheritdoc/>
        public virtual byte[] DeriveKey(byte[] keyExchangeData) => throw new NotSupportedException();

        /// <inheritdoc/>
        public virtual byte[] DeriveKey(IAsymmetricPublicKey publicKey) => throw new NotSupportedException();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _PublicKey?.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            _PublicKey?.Dispose();
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator byte[](AsymmetricPrivateKeyBase<tPublic, tPrivate> privateKey) => privateKey.Export();
    }
}
