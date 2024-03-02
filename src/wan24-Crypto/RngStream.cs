using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// RNG stream
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="rng">RNG (if <see langword="null"/>, <see cref="RND"/> will be used; will be disposed, if <see cref="RngStream{T}.DisposeRng"/> wasn't set to <see langword="false"/>)</param>
    public sealed class RngStream(in IRng? rng = null) : RngStream<IRng>(rng)
    {
        /// <summary>
        /// Singleton instance (which uses <see cref="RND"/> per default)
        /// </summary>
        public static RngStream Instance { get; set; } = new();
    }

    /// <summary>
    /// RNG stream
    /// </summary>
    /// <typeparam name="T">RNG type</typeparam>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="rng">RNG (if <see langword="null"/>, <see cref="RND"/> will be used; will be disposed, if <see cref="DisposeRng"/> wasn't set to <see langword="false"/>)</param>
    public class RngStream<T>(in T? rng = null) : StreamBase(), IRng where T : class, IRng
    {
        /// <summary>
        /// RNG (will be disposed, if <see cref="DisposeRng"/> wasn't set to <see langword="false"/>)
        /// </summary>
        public T? RNG { get; } = rng;

        /// <summary>
        /// Dispose the <see cref="RNG"/> when disposing?
        /// </summary>
        public bool DisposeRng { get; set; } = true;

        /// <inheritdoc/>
        public sealed override bool CanRead => true;

        /// <inheritdoc/>
        public sealed override bool CanSeek => false;

        /// <inheritdoc/>
        public sealed override bool CanWrite => false;

        /// <inheritdoc/>
        public sealed override long Length => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        /// <inheritdoc/>
        public sealed override bool CanTimeout => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override int ReadTimeout { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        /// <inheritdoc/>
        public sealed override int WriteTimeout { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        /// <inheritdoc/>
        public sealed override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override void SetLength(long value) => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override void Flush() => EnsureUndisposed(allowDisposing: true);

        /// <inheritdoc/>
        public sealed override Task FlushAsync(CancellationToken cancellationToken)
        {
            EnsureUndisposed(allowDisposing: true);
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public sealed override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback? callback, object? state)
            => base.BeginRead(buffer, offset, count, callback, state);

        /// <inheritdoc/>
        public sealed override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback? callback, object? state) => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override int EndRead(IAsyncResult asyncResult) => base.EndRead(asyncResult);

        /// <inheritdoc/>
        public sealed override void EndWrite(IAsyncResult asyncResult) => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override int ReadByte() => base.ReadByte();

        /// <inheritdoc/>
        public sealed override int Read(byte[] buffer, int offset, int count)
        {
            EnsureUndisposed();
            if (RNG is not null)
            {
                RNG.FillBytes(buffer.AsSpan(offset, count));
            }
            else
            {
                RND.FillBytes(buffer.AsSpan(offset, count));
            }
            return count;
        }

        /// <inheritdoc/>
        public sealed override int Read(Span<byte> buffer)
        {
            EnsureUndisposed();
            if (RNG is not null)
            {
                RNG.FillBytes(buffer);
            }
            else
            {
                RND.FillBytes(buffer);
            }
            return buffer.Length;
        }

        /// <inheritdoc/>
        public sealed override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            EnsureUndisposed();
            if (RNG is not null)
            {
                await RNG.FillBytesAsync(buffer.AsMemory(offset, count), cancellationToken).DynamicContext();
            }
            else
            {
                cancellationToken.ThrowIfCancellationRequested();
                await RND.FillBytesAsync(buffer.AsMemory(offset, count)).DynamicContext();
            }
            return count;
        }

        /// <inheritdoc/>
        public sealed override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (RNG is not null)
            {
                await RNG.FillBytesAsync(buffer, cancellationToken).DynamicContext();
            }
            else
            {
                cancellationToken.ThrowIfCancellationRequested();
                await RND.FillBytesAsync(buffer).DynamicContext();
            }
            return buffer.Length;
        }

        /// <inheritdoc/>
        public sealed override void WriteByte(byte value) => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override void Write(ReadOnlySpan<byte> buffer) => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        /// <inheritdoc/>
        public sealed override void Close() => base.Close();

        /// <inheritdoc/>
        public sealed override void CopyTo(Stream destination, int bufferSize) => base.CopyTo(destination, bufferSize);

        /// <inheritdoc/>
        public sealed override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken) => base.CopyToAsync(destination, bufferSize, cancellationToken);

        /// <inheritdoc/>
        public sealed override bool Equals(object? obj) => base.Equals(obj);

        /// <inheritdoc/>
        public sealed override int GetHashCode() => base.GetHashCode();

        /// <inheritdoc/>
        [Obsolete("This Remoting API is not supported and throws PlatformNotSupportedException.", DiagnosticId = "SYSLIB0010", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
        public sealed override object InitializeLifetimeService() => throw new PlatformNotSupportedException();

        /// <inheritdoc/>
        public byte[] GetBytes(in int count)
        {
            EnsureUndisposed();
            return RNG?.GetBytes(count) ?? RND.GetBytes(count);
        }

        /// <inheritdoc/>
        public Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            cancellationToken.ThrowIfCancellationRequested();
            return RNG?.GetBytesAsync(count, cancellationToken) ?? RND.GetBytesAsync(count);
        }

        /// <inheritdoc/>
        public Span<byte> FillBytes(in Span<byte> buffer)
        {
            EnsureUndisposed();
            if (RNG is not null) return RNG.FillBytes(buffer);
            RND.FillBytes(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (RNG is not null) return await RNG.FillBytesAsync(buffer, cancellationToken).DynamicContext();
            cancellationToken.ThrowIfCancellationRequested();
            await RND.FillBytesAsync(buffer).DynamicContext();
            return buffer;
        }

        /// <inheritdoc/>
        protected sealed override void Dispose(bool disposing)
        {
            if (DisposeRng) RNG?.TryDispose();
            base.Dispose(disposing);
        }

        /// <inheritdoc/>
        protected sealed override async Task DisposeCore()
        {
            if (DisposeRng && RNG is not null) await RNG.TryDisposeAsync().DynamicContext();
            await base.DisposeCore().DynamicContext();
        }
    }
}
