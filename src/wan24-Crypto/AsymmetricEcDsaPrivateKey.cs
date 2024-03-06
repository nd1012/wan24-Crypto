using System.Security;
using System.Security.Cryptography;
using wan24.Core;
using wan24.ObjectValidation;

namespace wan24.Crypto
{
    /// <summary>
    /// Elliptic Curve DSA asymmetric private key
    /// </summary>
    public sealed record class AsymmetricEcDsaPrivateKey : AsymmetricPrivateKeyBase<AsymmetricEcDsaPublicKey, AsymmetricEcDsaPrivateKey>, ISignaturePrivateKey
    {
        /// <summary>
        /// Private key
        /// </summary>
        private ECDsa? _PrivateKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEcDsaPrivateKey() : base(AsymmetricEcDsaAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKeyData">Private key data (will be cloaked when disposing!)</param>
        public AsymmetricEcDsaPrivateKey(byte[] privateKeyData) : this() => KeyData = new(privateKeyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Private key (will be disposed!)</param>
        public AsymmetricEcDsaPrivateKey(ECDsa key) : this()
        {
            try
            {
                _PrivateKey = key;
                KeyData = new(key.ExportPkcs8PrivateKey());
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override int Bits => PrivateKey.KeySize;

        /// <inheritdoc/>
        public override AsymmetricEcDsaPublicKey PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PublicKey is not null) return _PublicKey;
                    ECDsa dsa = ECDsa.Create();
                    dsa.ImportSubjectPublicKeyInfo(PrivateKey.ExportSubjectPublicKeyInfo(), out _);
                    return _PublicKey = new(dsa);
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
            }
        }

        /// <summary>
        /// Private key (don't dispose - will be disposed when this private key instance disposes!)
        /// </summary>
        [NoValidation, SensitiveData]
        public ECDsa PrivateKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PrivateKey is not null) return _PrivateKey;
                    _PrivateKey = ECDsa.Create();
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
        public override byte[] SignHashRaw(byte[] hash)
        {
            try
            {
                EnsureUndisposed();
                if (CryptoHelper.StrictPostQuantumSafety) throw new InvalidOperationException($"Post quantum safety-forced - {Algorithm.Name} isn't post quantum");
                if (DeniedAlgorithms.IsAsymmetricAlgorithmDenied(Algorithm.Value))
                    throw CryptographicException.From(new SecurityException($"Asymmetric algorithm {Algorithm.DisplayName} was denied"));
                return PrivateKey.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
            }
            catch(CryptographicException)
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

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            _PrivateKey?.Dispose();
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricEcDsaPublicKey(AsymmetricEcDsaPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricEcDsaPrivateKey(byte[] data) => Import<AsymmetricEcDsaPrivateKey>(data);
    }
}
