namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an asymmetric private key
    /// </summary>
    public interface IAsymmetricPrivateKey : IAsymmetricKey
    {
        /// <summary>
        /// Public key (don't dispose - will be disposed, when the private key instance is disposing!)
        /// </summary>
        IAsymmetricPublicKey PublicKey { get; }
        /// <summary>
        /// Get a copy
        /// </summary>
        /// <returns>Copy</returns>
        IAsymmetricPrivateKey GetCopy();
    }
}
