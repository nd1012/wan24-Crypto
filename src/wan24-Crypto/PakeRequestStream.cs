using System.Diagnostics.Contracts;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE request stream
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="source">Source stream (contents will be copied to the <see cref="Cipher"/> which is going to be set using 
    /// <see cref="SetCipher(in Stream, in TaskScheduler?, in bool)"/>; won't be disposed)</param>
    /// <param name="bufferSize">Buffer size in bytes</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public sealed class PakeRequestStream(in Stream source, in int bufferSize, in CancellationToken cancellationToken = default)
        : BackgroundProcessingStreamBase(bufferSize, cancellationToken)
    {
        /// <summary>
        /// Source stream (contents will be copied to the <see cref="Cipher"/> which is going to be set using 
        /// <see cref="SetCipher(in Stream, in TaskScheduler?, in bool)"/>; won't be disposed)
        /// </summary>
        public Stream Source { get; } = source;

        /// <summary>
        /// Cipher stream (won't be disposed; unset after the copy process did finish)
        /// </summary>
        public Stream? Cipher { get; private set; }

        /// <inheritdoc/>
        public override bool CanWrite => true;

        /// <summary>
        /// Set the <see cref="Cipher"/> and start processing in the background
        /// </summary>
        /// <param name="cipher">Cipher stream (must use this instance as final output target stream; won't be disposed)</param>
        /// <param name="scheduler">Task scheduler to use</param>
        /// <param name="longRunning">If long running</param>
        public void SetCipher(in Stream cipher, in TaskScheduler? scheduler = null, in bool longRunning = true)
        {
            EnsureUndisposed();
            if (Cipher is not null || DidProcess) throw new InvalidOperationException();
            Scheduler = scheduler;
            LongRunning = longRunning;
            Cipher = cipher;
            StartProcessing();
        }

        /// <inheritdoc/>
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => WriteIntAsync(buffer, cancellationToken);

        /// <inheritdoc/>
        protected override async Task ProcessAsync(CancellationToken cancellationToken)
        {
            Contract.Assert(Cipher is not null);
            try
            {
                await Source.CopyToAsync(Cipher, cancellationToken).DynamicContext();
            }
            finally
            {
                Cipher = null;
            }
        }
    }
}
