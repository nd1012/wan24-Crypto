using System.Security;

namespace wan24.Crypto
{
    /// <summary>
    /// Private asymmetric void key
    /// </summary>
    public sealed record class AsymmetricVoidPrivateKey : AsymmetricPrivateKeyBase<AsymmetricVoidPublicKey, AsymmetricVoidPrivateKey>, ISignaturePrivateKey, IKeyExchangePrivateKey
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <exception cref="NotSupportedException">Not supported</exception>
        public AsymmetricVoidPrivateKey() : base(AsymmetricVoidAlgorithm.ALGORITHM_NAME) => throw new NotSupportedException();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        /// <exception cref="NotSupportedException">Notsupported</exception>
        public AsymmetricVoidPrivateKey(in byte[] keyData) : base(AsymmetricVoidAlgorithm.ALGORITHM_NAME) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override AsymmetricVoidPublicKey PublicKey => throw new NotSupportedException();

        /// <inheritdoc/>
        public override int Bits => throw new NotSupportedException();

        /// <inheritdoc/>
        (byte[] Key, byte[] KeyExchangeData) IKeyExchange.GetKeyExchangeData() => throw new NotSupportedException();

        /// <inheritdoc/>
        protected override bool EnsureAllowedCurve(in bool throwIfDenied = true)
        {
            if (!throwIfDenied) return false;
            throw CryptographicException.From(new SecurityException("A VIOD algorithm private key can't be used"));
        }

        /// <inheritdoc/>
        protected override bool EnsurePqcRequirement(in bool throwIfRequirementMismatch = true)
        {
            if (!throwIfRequirementMismatch) return false;
            throw CryptographicException.From(new SecurityException("A VIOD algorithm private key can't be used"));
        }
    }
}
