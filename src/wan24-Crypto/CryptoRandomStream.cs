using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto random stream (uses <see cref="RND"/> for reading cryptographic random bytes into the given buffers)
    /// </summary>
    public sealed class CryptoRandomStream : StreamBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        private CryptoRandomStream() : base() { }

        /// <summary>
        /// Singleton instance
        /// </summary>
        public static CryptoRandomStream Instance { get; } = new();

        /// <inheritdoc/>
        public override bool CanRead => true;

        /// <inheritdoc/>
        public override bool CanSeek => false;

        /// <inheritdoc/>
        public override bool CanWrite => false;

        /// <inheritdoc/>
        public override long Length => throw new NotSupportedException();

        /// <inheritdoc/>
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        /// <inheritdoc/>
        public override void Flush() { }

        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
        {
            RND.FillBytes(buffer.AsSpan(offset, count));
            return count;
        }

        /// <inheritdoc/>
        public override int Read(Span<byte> buffer)
        {
            RND.FillBytes(buffer);
            return buffer.Length;
        }

        /// <inheritdoc/>
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await RND.FillBytesAsync(buffer.AsMemory(offset, count)).DynamicContext();
            return count;
        }

        /// <inheritdoc/>
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await RND.FillBytesAsync(buffer).DynamicContext();
            return buffer.Length;
        }

        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override void SetLength(long value) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override void CopyTo(Stream destination, int bufferSize) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
