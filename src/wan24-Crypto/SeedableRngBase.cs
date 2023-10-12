namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a seedable RNG
    /// </summary>
    public abstract class SeedableRngBase : RngBase, ISeedableRng
    {
        /// <summary>
        /// Constructor
        /// </summary>
        protected SeedableRngBase() : base() { }

        /// <inheritdoc/>
        public abstract void AddSeed(ReadOnlySpan<byte> seed);

        /// <inheritdoc/>
        public abstract Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default);
    }
}
