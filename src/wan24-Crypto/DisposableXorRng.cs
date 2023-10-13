using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// RNG which combines two or more RNGs with XOR
    /// </summary>
    public sealed class DisposableXorRng : DisposableRngBase
    {
        /// <summary>
        /// Adapted XOR RNG
        /// </summary>
        private readonly XorRng AdaptedRng;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rngs">RNGs to use (will be disposed, if possible!)</param>
        public DisposableXorRng(params IRng[] rngs) : base()
        {
            if (rngs.Length < 2) throw new ArgumentOutOfRangeException(nameof(rngs), "Need at last 2 RNGs");
            AdaptedRng = new(rngs);
            RNG = rngs;
        }

        /// <summary>
        /// RNGs to use
        /// </summary>
        public IRng[] RNG { get; }

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer) => AdaptedRng.FillBytes(buffer);

        /// <inheritdoc/>
        public override Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => AdaptedRng.FillBytesAsync(buffer, cancellationToken);

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => RNG.TryDisposeAll();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await RNG.TryDisposeAllAsync().DynamicContext();
    }
}
