﻿using System.Security.Cryptography;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Elliptic Curve Diffie Hellman asymmetric private key
    /// </summary>
    public sealed class AsymmetricEcDiffieHellmanPrivateKey : AsymmetricPrivateKeyBase<AsymmetricEcDiffieHellmanPublicKey, AsymmetricEcDiffieHellmanPrivateKey>, IKeyExchangePrivateKey
    {
        /// <summary>
        /// Private key
        /// </summary>
        private ECDiffieHellman? _PrivateKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEcDiffieHellmanPrivateKey() : base(AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKeyData">Private key data (will be cloaked when disposing!)</param>
        public AsymmetricEcDiffieHellmanPrivateKey(byte[] privateKeyData) : this() => KeyData = new(privateKeyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Private key (will be disposed!)</param>
        public AsymmetricEcDiffieHellmanPrivateKey(ECDiffieHellman key) : this()
        {
            try
            {
                _PrivateKey = key;
                KeyData = new(key.ExportECPrivateKey());
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override int Bits => PrivateKey.KeySize;

        /// <inheritdoc/>
        public override AsymmetricEcDiffieHellmanPublicKey PublicKey => _PublicKey ??= new(PrivateKey.PublicKey);

        /// <summary>
        /// Private key (don't dispose - will be disposed when this private key instance disposes!)
        /// </summary>
        public ECDiffieHellman PrivateKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PrivateKey != null) return _PrivateKey;
                    _PrivateKey = ECDiffieHellman.Create();
                    int red;
                    try
                    {
                        _PrivateKey.ImportECPrivateKey(KeyData.Span, out red);
                    }
                    catch
                    {
                        _PrivateKey.Dispose();
                        _PrivateKey = null;
                        throw;
                    }
                    if (red != KeyData.Length)
                    {
                        _PrivateKey.Dispose();
                        _PrivateKey = null;
                        throw new InvalidDataException("The key data wasn't fully used");
                    }
                    return _PrivateKey;
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
            }
        }

        /// <inheritdoc/>
        public override (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData(IAsymmetricPublicKey? publicKey = null, CryptoOptions? options = null)
        {
            try
            {
                EnsureUndisposed();
                if (CryptoHelper.StrictPostQuantumSafety) throw new InvalidOperationException($"Post quantum safety-forced - {Algorithm.Name} isn't post quantum");
                publicKey ??= options?.PublicKey ?? options?.PrivateKey?.PublicKey ?? PublicKey;
                if (publicKey is not AsymmetricEcDiffieHellmanPublicKey) throw new ArgumentException("Public ECDH key required", nameof(publicKey));
                byte[] ked = (byte[])PublicKey.KeyData.Array.Clone();
                return (DeriveKey((byte[])publicKey.KeyData.Array.Clone()), ked);
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
        public override byte[] DeriveKey(byte[] keyExchangeData)
        {
            try
            {
                EnsureUndisposed();
                if (CryptoHelper.StrictPostQuantumSafety) throw new InvalidOperationException($"Post quantum safety-forced - {Algorithm.Name} isn't post quantum");
                using AsymmetricEcDiffieHellmanPublicKey publicKey = new((byte[])keyExchangeData.Clone());
                return PrivateKey.DeriveKeyMaterial(publicKey.PublicKey);
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
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _PrivateKey?.Dispose();
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricEcDiffieHellmanPublicKey(AsymmetricEcDiffieHellmanPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricEcDiffieHellmanPrivateKey(byte[] data) => Import<AsymmetricEcDiffieHellmanPrivateKey>(data);
    }
}
