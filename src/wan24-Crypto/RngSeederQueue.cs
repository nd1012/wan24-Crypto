using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// RNG seeder (added seeds will be copied)
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="capacity">Queue capacity</param>
    /// <param name="rng">Target RNG to seed</param>
    public class RngSeederQueue(in int capacity, in ISeedableRng rng) : ItemQueueWorkerBase<byte[]>(capacity), ISeedableRng
    {

        /// <summary>
        /// Seeded target RNG
        /// </summary>
        public ISeedableRng RNG { get; } = rng;

        /// <inheritdoc/>
        public virtual void AddSeed(ReadOnlySpan<byte> seed)
        {
            byte[] seedBytes = seed.ToArray();
            try
            {
                if (!TryEnqueue(seedBytes)) seedBytes.Clear();
            }
            catch
            {
                seedBytes.Clear();
                throw;
            }
        }

        /// <inheritdoc/>
        public virtual async Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            AddSeed(seed.Span);
        }

        /// <inheritdoc/>
        protected override async Task ProcessItem(byte[] item, CancellationToken cancellationToken)
        {
            using SecureByteArrayStructSimple seed = new(item);
            await RNG.AddSeedAsync(seed.Memory, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        Span<byte> IRng.FillBytes(in Span<byte> buffer) => throw new NotSupportedException();

        /// <inheritdoc/>
        Task<Memory<byte>> IRng.FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken) => throw new NotSupportedException();

        /// <inheritdoc/>
        byte[] IRng.GetBytes(in int count) => throw new NotSupportedException();

        /// <inheritdoc/>
        Task<byte[]> IRng.GetBytesAsync(int count, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
