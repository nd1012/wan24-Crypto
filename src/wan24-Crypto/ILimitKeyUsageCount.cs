namespace wan24.Crypto
{
    /// <summary>
    /// Interface for types which limit a key usage count
    /// </summary>
    public interface ILimitKeyUsageCount
    {
        /// <summary>
        /// Maximum key usage count (before a fresh key should be used for processing more messages)
        /// </summary>
        long MaxKeyUsageCount { get; }
    }
}
