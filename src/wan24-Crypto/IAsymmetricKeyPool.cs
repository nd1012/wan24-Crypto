using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an asymmetric private key pool
    /// </summary>
    public interface IAsymmetricKeyPool : IInstancePool
    {
        /// <summary>
        /// Algorithm
        /// </summary>
        IAsymmetricAlgorithm Algorithm { get; }
        /// <summary>
        /// Options (returns a clone of the used options)
        /// </summary>
        CryptoOptions Options { get; }
        /// <summary>
        /// Get a key
        /// </summary>
        /// <returns>Asymmetric private key</returns>
        IAsymmetricPrivateKey GetKey();
        /// <summary>
        /// Get a key
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Asymmetric private key</returns>
        Task<IAsymmetricPrivateKey> GetKeyAsync(CancellationToken cancellationToken = default);
    }
}
