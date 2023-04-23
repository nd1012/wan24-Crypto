namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an asymmetric public key
    /// </summary>
    public interface IAsymmetricPublicKey : IAsymmetricKey
    {
        /// <summary>
        /// Get a copy
        /// </summary>
        /// <returns>Copy</returns>
        IAsymmetricPublicKey GetCopy();
    }
}
