using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Havege RNG
    /// </summary>
    public sealed class HavegeRng : DisposableRngBase
    {
        /// <summary>
        /// Havege RNG command
        /// </summary>
        public const string HAVEGE = "/usr/sbin/haveged";

        private readonly DisposableObjectPool<ProcessStream> Pool;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Random data stream pool capacity</param>
        public HavegeRng(in int capacity) : base() => Pool = new(capacity, () => ProcessStream.Create(HAVEGE, args: new string[] { "-n", "0" }));

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            EnsureUndisposed();
            using RentedObject<ProcessStream> havege = new(Pool);
            int red = havege.Object.Read(buffer);
            if (red != buffer.Length) throw new IOException($"Failed to read {red} byte from haveg process stream");
            return buffer;
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using RentedObject<ProcessStream> havege = new(Pool);
            int red = await havege.Object.ReadAsync(buffer, cancellationToken).DynamicContext();
            if (red != buffer.Length) throw new IOException($"Failed to read {red} byte from haveg process stream");
            return buffer;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => Pool.Dispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await Pool.DisposeAsync().DynamicContext();
    }
}
