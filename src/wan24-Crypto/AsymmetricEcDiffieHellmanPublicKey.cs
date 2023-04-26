﻿using System.Security.Cryptography;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Elliptic Curve Diffie Hellman asymmetric public key
    /// </summary>
    public sealed class AsymmetricEcDiffieHellmanPublicKey : AsymmetricPublicKeyBase
    {
        /// <summary>
        /// Public key
        /// </summary>
        private ECDiffieHellmanPublicKey? _PublicKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEcDiffieHellmanPublicKey() : base(AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKeyData">Public key data (will be cloaked when disposing!)</param>
        public AsymmetricEcDiffieHellmanPublicKey(byte[] publicKeyData) : this() => KeyData = new(publicKeyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Public key (will be disposed!)</param>
        public AsymmetricEcDiffieHellmanPublicKey(ECDiffieHellmanPublicKey key) : this()
        {
            try
            {
                _PublicKey = key;
                KeyData = new(key.ExportSubjectPublicKeyInfo());
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override int Bits => EllipticCurves.GetKeySize(PublicKey.ExportParameters().Curve);

        /// <summary>
        /// Public key (don't dispose - will be disposed when this public key instance disposes!)
        /// </summary>
        public ECDiffieHellmanPublicKey PublicKey
        {
            get
            {
                try
                {
                    if (_PublicKey != null) return _PublicKey;
                    using ECDiffieHellman dh = ECDiffieHellman.Create();
                    dh.ImportSubjectPublicKeyInfo(KeyData.Span, out int red);
                    if (red != KeyData.Length) throw new InvalidDataException("The key data wasn't fully used");
                    return _PublicKey = dh.PublicKey;
                }
                catch(Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
            }
        }

        /// <inheritdoc/>
        public override IAsymmetricPublicKey GetCopy() => new AsymmetricEcDiffieHellmanPublicKey((byte[])KeyData.Array.Clone());

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _PublicKey?.Dispose();
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public static implicit operator byte[](AsymmetricEcDiffieHellmanPublicKey publicKey) => publicKey.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricEcDiffieHellmanPublicKey(byte[] data) => data.ToObject<AsymmetricEcDiffieHellmanPublicKey>();
    }
}
