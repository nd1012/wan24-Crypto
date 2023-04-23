using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// Elliptic Curve DSA asymmetric private key
    /// </summary>
    public sealed class AsymmetricEcDsaPrivateKey : AsymmetricPrivateKeyBase<AsymmetricEcDsaPublicKey, AsymmetricEcDsaPrivateKey>, ISignaturePrivateKey
    {
        /// <summary>
        /// Private key
        /// </summary>
        private ECDsa? _PrivateKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEcDsaPrivateKey() : base() { }

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
                KeyData = new(key.ExportECPrivateKey());
            }
            catch(Exception ex)
            {
                throw new CryptographicException(ex.Message, ex);
            }
        }

        /// <inheritdoc/>
        public override string Algorithm => AsymmetricEcDsaAlgorithm.ALGORITHM_NAME;

        /// <inheritdoc/>
        public override int Bits => PrivateKey.KeySize;

        /// <inheritdoc/>
        public override AsymmetricEcDsaPublicKey PublicKey
        {
            get
            {
                try
                {
                    if (_PublicKey != null) return _PublicKey;
                    ECDsa dsa = ECDsa.Create();
                    dsa.ImportSubjectPublicKeyInfo(PrivateKey.ExportSubjectPublicKeyInfo(), out _);
                    return _PublicKey = new(dsa);
                }
                catch (Exception ex)
                {
                    throw new CryptographicException(ex.Message, ex);
                }
            }
        }

        /// <summary>
        /// Private key (don't dispose - will be disposed when this private key instance disposes!)
        /// </summary>
        public ECDsa PrivateKey
        {
            get
            {
                try
                {
                    if (_PrivateKey != null) return _PrivateKey;
                    _PrivateKey = ECDsa.Create();
                    _PrivateKey.ImportECPrivateKey(KeyData.Span, out int red);
                    if (red != KeyData.Length) throw new InvalidDataException("The key data wasn't fully used");
                    return _PrivateKey;
                }
                catch (Exception ex)
                {
                    throw new CryptographicException(ex.Message, ex);
                }
            }
        }

        /// <inheritdoc/>
        public override byte[] SignHashRaw(byte[] hash)
        {
            try
            {
                return PrivateKey.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
            }
            catch (Exception ex)
            {
                throw new CryptographicException(ex.Message, ex);
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _PrivateKey?.Dispose();
        }
    }
}
