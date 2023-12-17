using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <c>/dev/hwrng</c> RNG
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="streamPoolCapacity"><c>/dev/hwrng</c> stream pool capacity</param>
    public sealed class DevHwRng(in int streamPoolCapacity) : DisposableRngBase()
    {
        /// <summary>
        /// <c>/dev/hwrng</c> filename
        /// </summary>
        public const string HWRNG = "/dev/hwrng";

        /// <summary>
        /// <c>/dev/hwrng</c> stream pool
        /// </summary>
        private readonly DisposableObjectPool<Stream> HwRngPool = new(streamPoolCapacity, () => new FileStream(HWRNG, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            DateTime started = DateTime.Now;
            using RentedObject<Stream> random = new(HwRngPool);
            random.Object.ReadExactly(buffer);
            if (DateTime.Now - started > TimeSpan.FromSeconds(10))
                Logging.WriteWarning(
                    $"{HWRNG} doesn't get enough entropy for returning {buffer.Length} byte random data within 10 seconds (took {DateTime.Now - started} instead)"
                    );
            return buffer;
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            DateTime started = DateTime.Now;
            using RentedObject<Stream> random = new(HwRngPool);
            await random.Object.ReadExactlyAsync(buffer, cancellationToken).DynamicContext();
            if (DateTime.Now - started > TimeSpan.FromSeconds(10))
                Logging.WriteWarning(
                    $"{HWRNG} doesn't get enough entropy for returning {buffer.Length} byte random data within 10 seconds (took {DateTime.Now - started} instead)"
                    );
            return buffer;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => HwRngPool.Dispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await HwRngPool.DisposeAsync().DynamicContext();
    }
}
