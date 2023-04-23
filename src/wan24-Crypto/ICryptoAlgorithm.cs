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
        /// Is a post quantum algorithm?
        /// </summary>
        bool IsPostQuantum { get; }
    }
}
