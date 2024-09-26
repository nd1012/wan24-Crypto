using System.Collections.Immutable;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Auto-seed RNG wrapper (seeds the wrapped <see cref="ISeedableRng"/> by reading seed from a list of streams in an interval)
    /// </summary>
    public class AutoSeedRngWrapper<T> : DisposableBase, ISeedableRng where T : class, ISeedableRng
    {
        /// <summary>
        /// Seed timer
        /// </summary>
        protected readonly System.Timers.Timer SeedTimer;
        /// <summary>
        /// Seed length in bytes
        /// </summary>
        protected readonly int SeedLength;
        /// <summary>
        /// <see cref="SeedAsync"/> task
        /// </summary>
        protected Task? SeedTask = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="seedInterval">Seed interval</param>
        /// <param name="seedSources">Seed sources (will be disposed)</param>
        public AutoSeedRngWrapper(in TimeSpan seedInterval, params SeedSource[] seedSources) : base()
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(seedInterval, TimeSpan.Zero);
            ArgumentOutOfRangeException.ThrowIfLessThan(seedSources.Length, other: 1, nameof(seedSources));
            if (seedSources.Any(s => s.SeedLength < 1 || !s.Source.CanRead))
                throw new ArgumentException("Seed length of a seed source must be greater than zero, and source streams need to be readable", nameof(seedSources));
            SeedSources = [.. seedSources];
            SeedLength = SeedSources.Sum(s => s.SeedLength);
            SeedTimer = new(seedInterval)
            {
                AutoReset = false
            };
            SeedTimer.Elapsed += (s, e) => SeedTask = SeedAsync();
            SeedTimer.Start();
        }

        /// <summary>
        /// Seed sources
        /// </summary>
        public ImmutableArray<SeedSource> SeedSources { get; }

        /// <summary>
        /// Wrapped RNG (will be disposed)
        /// </summary>
        public required T RNG { get; init; }

        /// <summary>
        /// Last exception during seeding
        /// </summary>
        public Exception? LastException { get; protected set; }

        /// <inheritdoc/>
        public virtual void AddSeed(ReadOnlySpan<byte> seed)
        {
            EnsureUndisposed();
            RNG.AddSeed(seed);
        }

        /// <inheritdoc/>
        public virtual async Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            await RNG.AddSeedAsync(seed, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        public virtual Span<byte> FillBytes(in Span<byte> buffer)
        {
            EnsureUndisposed();
            return RNG.FillBytes(buffer);
        }

        /// <inheritdoc/>
        public virtual async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            return await RNG.FillBytesAsync(buffer, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        public virtual byte[] GetBytes(in int count)
        {
            EnsureUndisposed();
            return RNG.GetBytes(count);
        }

        /// <inheritdoc/>
        public virtual async Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            return await RNG.GetBytesAsync(count, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Seed
        /// </summary>
        protected virtual async Task SeedAsync()
        {
            await Task.Yield();
            try
            {
                using RentedMemory<byte> buffer = new(len: SeedLength, clean: false)
                {
                    Clear = true
                };
                Memory<byte> bufferMem = buffer.Memory;
                SeedSource current;
                for (int i = 0, len = SeedSources.Length, pos = 0; i < len; pos += current.SeedLength, i++)
                {
                    current = SeedSources[i];
                    await current.Source.ReadExactlyAsync(bufferMem.Slice(pos, current.SeedLength)).DynamicContext();
                }
                await RNG.AddSeedAsync(bufferMem).DynamicContext();
                SeedTimer.Start();
            }
            catch (ObjectDisposedException) when (IsDisposing)
            {
            }
            catch (Exception ex)
            {
                LastException = ex;
                ErrorHandling.Handle(new("Auto-seed RNG wrapper background seeding failed", ex, tag: this));
                RaiseOnError();
            }
            finally
            {
                SeedTask = null;
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            SeedTimer.Dispose();
            SeedTask?.GetAwaiter().GetResult();
            RNG.TryDispose();
            SeedSources.DisposeAll();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            SeedTimer.Dispose();
            if (SeedTask is Task seedTask) await seedTask.DynamicContext();
            await RNG.TryDisposeAsync().DynamicContext();
            await SeedSources.DisposeAllAsync().DynamicContext();
        }

        /// <summary>
        /// Delegate for an error handler
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Arguments</param>
        public delegate void Error_Delegate(AutoSeedRngWrapper<T> sender, EventArgs e);
        /// <summary>
        /// Raised on error (see <see cref="LastException"/>)
        /// </summary>
        public event Error_Delegate? OnError;
        /// <summary>
        /// Raise the <see cref="OnError"/> event
        /// </summary>
        protected virtual void RaiseOnError() => OnError?.Invoke(this, EventArgs.Empty);

        /// <summary>
        /// Seed source
        /// </summary>
        /// <remarks>
        /// Constructor
        /// </remarks>
        public record class SeedSource() : DisposableRecordBase()
        {
            /// <summary>
            /// Source stream
            /// </summary>
            public required Stream Source { get; init; }

            /// <summary>
            /// Seed length in bytes
            /// </summary>
            public required int SeedLength { get; init; }

            /// <inheritdoc/>
            protected override void Dispose(bool disposing) => Source.Dispose();

            /// <inheritdoc/>
            protected override async Task DisposeCore() => await Source.DisposeAsync().DynamicContext();
        }
    }
}
