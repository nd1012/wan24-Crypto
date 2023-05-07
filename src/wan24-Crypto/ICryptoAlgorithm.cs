namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a cryptographic algorithm
    /// </summary>
    public interface ICryptoAlgorithm
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
    }
}
