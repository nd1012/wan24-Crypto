using System.Security.Cryptography;
using wan24.Core;
using wan24.ObjectValidation;

namespace wan24.Crypto
{
    /// <summary>
    /// Elliptic Curve DSA asymmetric public key
    /// </summary>
    public sealed record class AsymmetricEcDsaPublicKey : AsymmetricPublicKeyBase, ISignaturePublicKey
    {
        /// <summary>
        /// Public key
        /// </summary>
        private ECDsa? _PublicKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEcDsaPublicKey() : base(AsymmetricEcDsaAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKeyData">Public key data (will be cloaked when disposing!)</param>
        public AsymmetricEcDsaPublicKey(byte[] publicKeyData) : this() => KeyData = new(publicKeyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Public key (will be disposed!)</param>
        public AsymmetricEcDsaPublicKey(ECDsa key) : this()
        {
            try
            {
                _PublicKey = key;
                KeyData = new(key.ExportSubjectPublicKeyInfo());
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override int Bits => PublicKey.KeySize;

        /// <summary>
        /// Public key (don't dispose - will be disposed when this public key instance disposes!)
        /// </summary>
        [NoValidation]
        public ECDsa PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PublicKey is not null) return _PublicKey;
                    _PublicKey = ECDsa.Create();
                    _PublicKey.ImportSubjectPublicKeyInfo(KeyData.Span, out int red);
                    if (red != KeyData.Length) throw new InvalidDataException("The key data wasn't fully used");
                    return _PublicKey;
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
            }
        }

        /// <inheritdoc/>
        public override IAsymmetricPublicKey GetCopy() => new AsymmetricEcDsaPublicKey(KeyData.Array.CloneArray());

        /// <inheritdoc/>
        public override bool ValidateSignatureRaw(byte[] signature, byte[] signedHash, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                bool res = PublicKey.VerifyHash(signedHash, signature, DSASignatureFormat.Rfc3279DerSequence);
                if (!res && throwOnError) throw new InvalidDataException("Signature validation failed");
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
        protected override bool ValidateSignatureInt(SignatureContainer signature, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                bool res = ValidateSignatureRaw(signature.Signature, signature.CreateSignatureHash());
                if (!res && throwOnError) throw new InvalidDataException("Signature validation failed");
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
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricEcDsaPublicKey(byte[] data) => Import<AsymmetricEcDsaPublicKey>(data);
    }
}
