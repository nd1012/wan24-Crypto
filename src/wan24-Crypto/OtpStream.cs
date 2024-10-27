using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// OTP stream
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="baseStream">Base stream</param>
    /// <param name="leaveOpen">Leave the base stream open when disposing?</param>
    public class OtpStream(in Stream baseStream, in bool leaveOpen = false) : OtpStream<Stream>(baseStream, leaveOpen) { }

    /// <summary>
    /// OTP stream
    /// </summary>
    /// <typeparam name="T">Wrapped stream type</typeparam>
    public class OtpStream<T> : WrapperStream<T> where T : Stream
    {
        /// <summary>
        /// OTP sequence synchronization
        /// </summary>
        protected readonly SemaphoreSync SequenceSync = new();

        /// <remarks>
        /// Constructor
        /// </remarks>
        /// <param name="baseStream">Base stream</param>
        /// <param name="leaveOpen">Leave the base stream open when disposing?</param>
        public OtpStream(in T baseStream, in bool leaveOpen = false) : base(baseStream, leaveOpen)
        {
            if (!baseStream.CanRead || !baseStream.CanWrite || !baseStream.CanSeek)
                throw new ArgumentException("Read-, writ- and seekable base stream required", nameof(baseStream));
        }

        /// <summary>
        /// Read an OTP sequence from the
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <param name="cancellationToken"></param>
        /// <returns>Context</returns>
        public async Task<Context> ReadOtpSequence(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            SemaphoreSyncContext ssc = await SequenceSync.SyncContextAsync(cancellationToken).DynamicContext();
            try
            {
                long len = Length;
                if (buffer.Length > len) throw new IOException("Not enough OTP data available to fill the buffer");
                long offset = Position = len - buffer.Length;
                await ReadExactlyAsync(buffer, cancellationToken).DynamicContext();
                return new(this, offset, ssc);
            }
            catch
            {
                ssc.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Synchronize the OTP sequence offset
        /// </summary>
        /// <param name="offset">New offset</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task SynchronizeOtpSequenceOffsetAsync(long offset, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            long pos = Position = Length - offset,
                len = this.GetRemainingBytes();
            await RngStream.Instance.CopyExactlyPartialToAsync(this, len, cancellationToken: cancellationToken).DynamicContext();
            Position = pos;
            using (ZeroStream zero = new())
                await zero.CopyExactlyPartialToAsync(this, len, cancellationToken: cancellationToken).DynamicContext();
            SetLength(pos);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            SequenceSync.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            SequenceSync.Dispose();
        }

        /// <summary>
        /// OTP sequence synchronization context
        /// </summary>
        /// <remarks>
        /// Constructor
        /// </remarks>
        /// <param name="stream">Stream</param>
        /// <param name="offset">Synchronization offset</param>
        /// <param name="ssc">Sequence synchronization context</param>
        public class Context(in OtpStream<T> stream, in long offset, in SemaphoreSyncContext ssc) : DisposableBase()
        {
            /// <summary>
            /// Sequence synchronization context
            /// </summary>
            protected readonly SemaphoreSyncContext SyncContext = ssc;

            /// <summary>
            /// Stream
            /// </summary>
            public OtpStream<T> Stream { get; } = stream;

            /// <summary>
            /// Synchronization offset
            /// </summary>
            public long Offset { get; } = offset;

            /// <summary>
            /// If to synchronize the <see cref="Stream"/> when disposing
            /// </summary>
            public bool Synchronize { get; set; }

            /// <inheritdoc/>
            protected override void Dispose(bool disposing)
            {
                if (Synchronize)
                    try
                    {
                        Stream.SynchronizeOtpSequenceOffsetAsync(Offset).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        ErrorHandling.Handle(new("Failed to synchronize the OTP sequence offset", ex, tag: this));
                    }
                SyncContext.Dispose();
            }

            /// <inheritdoc/>
            protected override async Task DisposeCore()
            {
                if (Synchronize)
                    try
                    {
                        await Stream.SynchronizeOtpSequenceOffsetAsync(Offset).DynamicContext();
                    }
                    catch (Exception ex)
                    {
                        ErrorHandling.Handle(new("Failed to synchronize the OTP sequence offset", ex, tag: this));
                    }
                SyncContext.Dispose();
            }
        }
    }
}
