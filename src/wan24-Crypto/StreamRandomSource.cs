using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Stream RND source
    /// </summary>
    /// <param name="stream">Stream (will be wrapped with <see cref="SynchronizedStream"/> and disposed)</param>
    public class StreamRandomSource(in Stream stream) : DisposableRngBase()
    {
        /// <summary>
        /// Stream (will be disposed)
        /// </summary>
        public SynchronizedStream Stream { get; } = new SynchronizedStream(stream);

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            Stream.Read(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Stream.ReadAsync(buffer, cancellationToken).DynamicContext();
            return buffer;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => Stream.Dispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await Stream.DisposeAsync().DynamicContext();
    }
}
