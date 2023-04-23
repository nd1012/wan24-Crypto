using System.Security.Cryptography;

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
        public AsymmetricEcDiffieHellmanPrivateKey() : base() { }

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
            catch(Exception ex)
            {
                throw new CryptographicException(ex.Message, ex);
            }
        }

        /// <inheritdoc/>
        public override string Algorithm => AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME;

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
                catch(Exception ex)
                {
                    throw new CryptographicException(ex.Message, ex);
                }
            }
        }

        /// <inheritdoc/>
        public override byte[] GetKeyExchangeData(CryptoOptions? options = null) => (byte[])PublicKey.KeyData.Array.Clone();

        /// <inheritdoc/>
        public override byte[] DeriveKey(byte[] keyExchangeData)
        {
            try
            {
                using AsymmetricEcDiffieHellmanPublicKey publicKey = new((byte[])keyExchangeData.Clone());
                return PrivateKey.DeriveKeyMaterial(publicKey.PublicKey);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
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
