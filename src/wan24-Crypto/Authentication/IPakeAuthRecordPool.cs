using wan24.Core;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE authentication record pool
    /// </summary>
    public interface IPakeAuthRecordPool : IInstancePool<PakeAuthRecord>
    {
        /// <summary>
        /// Options (returns a clone of the used options)
        /// </summary>
        CryptoOptions Options { get; }
        /// <summary>
        /// Get a record
        /// </summary>
        /// <returns>PAKE authentication record</returns>
        IPakeAuthRecord GetRecord();
        /// <summary>
        /// Get a key
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE authentication record</returns>
        Task<IPakeAuthRecord> GetRecordAsync(CancellationToken cancellationToken = default);
    }
}
