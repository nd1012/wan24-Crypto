using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// RNG seeder (added seeds will be copied)
    /// </summary>
    public class RngSeederQueue : ItemQueueWorkerBase<byte[]>, ISeedableRng
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Queue capacity</param>
        /// <param name="rng">Target RNG to seed</param>
        public RngSeederQueue(in int capacity, in ISeedableRng rng) : base(capacity) => RNG = rng;

        /// <summary>
        /// Seeded target RNG
        /// </summary>
        public ISeedableRng RNG { get; }

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
    }
}
