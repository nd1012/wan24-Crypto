namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a disposable seedable RNG
    /// </summary>
    public abstract class DisposableSeedableRngBase : DisposableRngBase, ISeedableRng
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="asyncDisposing">Asynchronous disposing?</param>
        protected DisposableSeedableRngBase(bool asyncDisposing = true) : base(asyncDisposing) { }

        /// <inheritdoc/>
        public abstract void AddSeed(ReadOnlySpan<byte> seed);

        /// <inheritdoc/>
        public abstract Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default);
    }
}
