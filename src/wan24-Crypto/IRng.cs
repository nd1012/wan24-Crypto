namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an RNG
    /// </summary>
    public interface IRng
    {
        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="count">Count</param>
        /// <returns>Random bytes</returns>
        byte[] GetBytes(in int count);
        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="count">Count</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Random bytes</returns>
        Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default);
        /// <summary>
        /// Fill random bytes
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <returns>Random bytes</returns>
        Span<byte> FillBytes(in Span<byte> buffer);
        /// <summary>
        /// Fill random bytes
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Random bytes</returns>
        Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);
    }
}
