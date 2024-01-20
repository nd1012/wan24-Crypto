using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Havege RNG
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="capacity">Random data stream pool capacity</param>
    public sealed class HavegeRng(in int capacity) : DisposableRngBase()
    {
        /// <summary>
        /// Havege RNG command
        /// </summary>
        public const string HAVEGE = "/usr/sbin/haveged";

        /// <summary>
        /// Havege CLI arguments
        /// </summary>
        private static readonly string[] HavegeArgs = ["-n", "0"];

        /// <summary>
        /// Havege stream pool
        /// </summary>
        private readonly DisposableObjectPool<ProcessStream> Pool = new(capacity, () => ProcessStream.Create(HAVEGE, args: HavegeArgs));

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            EnsureUndisposed();
            using RentedObject<ProcessStream> havege = new(Pool);
            havege.Object.ReadExactly(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            RentedObject<ProcessStream> havege = new(Pool);
            await using(havege.DynamicContext()) await havege.Object.ReadExactlyAsync(buffer, cancellationToken).DynamicContext();
            return buffer;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => Pool.Dispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await Pool.DisposeAsync().DynamicContext();
    }
}
