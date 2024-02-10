using System.Security.Cryptography;
using wan24.Core;
using wan24.ObjectValidation;

namespace wan24.Crypto
{
    /// <summary>
    /// Elliptic Curve Diffie Hellman asymmetric private key
    /// </summary>
    public sealed record class AsymmetricEcDiffieHellmanPrivateKey : AsymmetricPrivateKeyBase<AsymmetricEcDiffieHellmanPublicKey, AsymmetricEcDiffieHellmanPrivateKey>, IKeyExchangePrivateKey
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
                KeyData = new(key.ExportPkcs8PrivateKey());
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
        [NoValidation, SensitiveData]
        public ECDiffieHellman PrivateKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PrivateKey is not null) return _PrivateKey;
                    _PrivateKey = ECDiffieHellman.Create();
                    int red;
                    try
                    {
                        _PrivateKey.ImportPkcs8PrivateKey(KeyData.Span, out red);
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
                return (DeriveKey(publicKey.KeyData.Array.CloneArray()), PublicKey.KeyData.Array.CloneArray());
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
        (byte[] Key, byte[] KeyExchangeData) IKeyExchange.GetKeyExchangeData() => GetKeyExchangeData();

        /// <inheritdoc/>
        public override byte[] DeriveKey(byte[] keyExchangeData)
        {
            try
            {
                EnsureUndisposed();
                if (CryptoHelper.StrictPostQuantumSafety) throw new InvalidOperationException($"Post quantum safety-forced - {Algorithm.Name} isn't post quantum");
                using AsymmetricEcDiffieHellmanPublicKey publicKey = new(keyExchangeData);
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
        public override byte[] DeriveKey(IAsymmetricPublicKey publicKey)
        {
            try
            {
                EnsureUndisposed();
                if (CryptoHelper.StrictPostQuantumSafety) throw new InvalidOperationException($"Post quantum safety-forced - {Algorithm.Name} isn't post quantum");
                if (publicKey is not AsymmetricEcDiffieHellmanPublicKey key) throw new ArgumentException("Public ECDH key required", nameof(publicKey));
                return PrivateKey.DeriveKeyMaterial(key.PublicKey);
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
            _PrivateKey?.PublicKey?.Dispose();
            _PrivateKey?.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            _PrivateKey?.PublicKey?.Dispose();
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
