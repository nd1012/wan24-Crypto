using wan24.Core;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE authentication record pool
    /// </summary>
    public sealed class PakeAuthRecordPool : InstancePool<PakeAuthRecord>, IPakeAuthRecordPool
    {
        /// <summary>
        /// PAKE instance
        /// </summary>
        private readonly Pake Pake;
        /// <summary>
        /// PAKE value length in bytes
        /// </summary>
        private readonly int ValueLength;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Capacity</param>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        public PakeAuthRecordPool(in int capacity, in CryptoOptions? options = null) : base(capacity, FactoryAsync)
        {
            Pake = new(options ?? Pake.DefaultOptions);
            ValueLength = MacHelper.GetAlgorithm(Pake.Options.MacAlgorithm!).MacLength;
            ErrorSource = Constants.CRYPTO_ERROR_SOURCE;
        }

        /// <inheritdoc/>
        public CryptoOptions Options => Pake.Options.Clone();

        /// <inheritdoc/>
        public IPakeAuthRecord GetRecord() => GetOne();

        /// <inheritdoc/>
        public async Task<IPakeAuthRecord> GetRecordAsync(CancellationToken cancellationToken) => await GetOneAsync(cancellationToken).DynamicContext();

        /// <summary>
        /// Private key factory
        /// </summary>
        /// <param name="pool">Pool</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Private key</returns>
        private static Task<PakeAuthRecord> FactoryAsync(IInstancePool<PakeAuthRecord> pool, CancellationToken cancellationToken)
        {
            PakeAuthRecordPool recordPool = (PakeAuthRecordPool)pool;
            return PakeAuthRecord.CreateRandomAsync(recordPool.Pake, valueLength: recordPool.ValueLength);
        }
    }
}
