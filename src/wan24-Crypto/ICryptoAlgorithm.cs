using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a cryptographic algorithm
    /// </summary>
    public interface ICryptoAlgorithm : IStatusProvider
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        string Name { get; }
        /// <summary>
        /// Algorithm value
        /// </summary>
        int Value { get; }
        /// <summary>
        /// Is a post quantum algorithm ("post quantum-safe")?
        /// </summary>
        bool IsPostQuantum { get; }
        /// <summary>
        /// Display name
        /// </summary>
        string DisplayName { get; }
        /// <summary>
        /// Uses a TPM?
        /// </summary>
        bool UsesTpm { get; }
        /// <summary>
        /// Is supported?
        /// </summary>
        bool IsSupported { get; }
        /// <summary>
        /// Ensure this algorithm is allowed in the current configuration
        /// </summary>
        /// <param name="throwIfDenied">Throw an exception, if this algorithm isn't allowed?</param>
        /// <returns>If this algorithm is allowed in the current configuration</returns>
        /// <exception cref="CryptographicException">This algorithm is not allowed in the current configuration</exception>
        bool EnsureAllowed(in bool throwIfDenied = true);
    }
}
