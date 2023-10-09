using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Random data generator (uses <c>/dev/urandom</c>, if possible; defaults to <see cref="RandomNumberGenerator"/>)
    /// </summary>
    public class RandomDataGenerator : HostedServiceBase
    {
        /// <summary>
        /// Random data
        /// </summary>
        protected readonly BlockingBufferStream RandomData;
        /// <summary>
        /// Use the RNG delegates?
        /// </summary>
        protected readonly bool UseRng = false;
        /// <summary>
        /// RNG
        /// </summary>
        protected readonly RND.RNG_Delegate Rng = RND._FillBytes;
        /// <summary>
        /// RNG
        /// </summary>
        protected readonly RND.RNGAsync_Delegate RngAsync = RND._FillBytesAsync;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Capacity in bytes</param>
        public RandomDataGenerator(in int capacity) : base() => RandomData = new(capacity, clear: true);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Capacity in bytes</param>
        /// <param name="useRnd">Use the <see cref="RND"/> methods?</param>
        public RandomDataGenerator(in int capacity, in bool useRnd) : this(capacity) => UseRng = useRnd;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Capacity in bytes</param>
        /// <param name="rng">RNG</param>
        /// <param name="rngAsync">RNG</param>
        public RandomDataGenerator(in int capacity, in RND.RNG_Delegate rng, in RND.RNGAsync_Delegate rngAsync) : this(capacity)
        {
            Rng = rng;
            RngAsync = rngAsync;
            UseRng = true;
        }

        /// <summary>
        /// Use fallback methods?
        /// </summary>
        public bool UseFallback { get; set; } = true;

        /// <summary>
        /// Use <c>/dev/urandom</c>, if available?
        /// </summary>
        public bool UseDevUrandom { get; set; } = RND.UseDevUrandom;

        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="count">Count</param>
        /// <returns>Random bytes</returns>
        public byte[] GetBytes(in int count)
        {
            EnsureUndisposed();
            if (!IsRunning) throw new InvalidOperationException();
            byte[] res = new byte[count];
            if (UseFallback)
            {
                int red = RandomData.TryRead(res);
                if (red != count) Rng(res.AsSpan(red));
            }
            else if (RandomData.Read(res) != count)
            {
                throw new IOException("Failed to read random bytes");
            }
            return res;
        }

        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="count">Count</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Random bytes</returns>
        public async Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (!IsRunning) throw new InvalidOperationException();
            byte[] res = new byte[count];
            if (UseFallback)
            {
                int red = RandomData.TryRead(res);
                if (red != count) await RngAsync(res.AsMemory(red)).DynamicContext();
            }
            else if(await RandomData.ReadAsync(res, cancellationToken).DynamicContext() != count)
            {
                throw new IOException("Failed to read random bytes");
            }
            return res;
        }

        /// <summary>
        /// Fill random bytes
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <returns>Random bytes</returns>
        public Span<byte> FillBytes(in Span<byte> buffer)
        {
            EnsureUndisposed();
            if (!IsRunning) throw new InvalidOperationException();
            if (UseFallback)
            {
                int red = RandomData.TryRead(buffer);
                if (red != buffer.Length) Rng(buffer[red..]);
            }
            else if (RandomData.Read(buffer) != buffer.Length)
            {
                throw new IOException("Failed to read random bytes");
            }
            return buffer;
        }

        /// <summary>
        /// Fill random bytes
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Random bytes</returns>
        public async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (!IsRunning) throw new InvalidOperationException();
            if (UseFallback)
            {
                int red = RandomData.TryRead(buffer.Span);
                if (red != buffer.Length) await RngAsync(buffer[red..]).DynamicContext();
            }
            else if (await RandomData.ReadAsync(buffer, cancellationToken).DynamicContext() != buffer.Length)
            {
                throw new IOException("Failed to read random bytes");
            }
            return buffer;
        }

        /// <summary>
        /// Add seed to the RNG
        /// </summary>
        /// <param name="seed">Seed</param>
        public virtual void AddSeed(ReadOnlySpan<byte> seed)
        {
            if (RND.Generator != this) RND.AddSeed(seed);
            else RND.AddURandomSeed(seed);
        }

        /// <summary>
        /// Add seed to the RNG
        /// </summary>
        /// <param name="seed">Seed</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public virtual Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
            => RND.Generator != this
                ? RND.AddSeedAsync(seed, cancellationToken)
                : RND.AddURandomSeedAsync(seed, cancellationToken);

        /// <summary>
        /// Fill a buffer with random data (used as fallback; override to define a custom fallback RNG, when not using the <see cref="Rng"/> and <see cref="RngAsync"/> delegates)
        /// </summary>
        /// <param name="buffer">Buffer</param>
        protected virtual void Fill(in Span<byte> buffer) => Rng(buffer);

        /// <summary>
        /// Fill a buffer with random data (used as fallback; override to define a custom fallback RNG, when not using the <see cref="Rng"/> and <see cref="RngAsync"/> delegates)
        /// </summary>
        /// <param name="buffer">Buffer</param>
        protected virtual Task FillAsync(Memory<byte> buffer) => RngAsync(buffer);

        /// <inheritdoc/>
        protected override async Task WorkerAsync()
        {
            if (UseRng)
            {
                // Use the custom RNG
                ValueTask writeTask = ValueTask.CompletedTask;
                using RentedArrayStructSimple<byte> buffer = new(Math.Min(Settings.BufferSize, RandomData.BufferSize), clean: false)
                {
                    Clear = true
                };
                while (!CancelToken.IsCancellationRequested)
                {
                    await FillAsync(buffer.Memory).DynamicContext();
                    if (!CancelToken.IsCancellationRequested)
                        await writeTask.AsTask().WaitAsync(CancelToken).DynamicContext();
                    if (!CancelToken.IsCancellationRequested)
                        writeTask = RandomData.WriteAsync(buffer.Memory, CancelToken);
                }
                await writeTask.AsTask().WaitAsync(CancelToken).DynamicContext();
                return;
            }
            else if(UseDevUrandom && RND.HasDevUrandom)
            {
                // Use /dev/urandom
                try
                {
                    Stream urandom = RND.GetDevUrandom();
                    await using (urandom.DynamicContext()) await urandom.CopyToAsync(RandomData, CancelToken).DynamicContext();
                    return;
                }
                catch(Exception ex)
                {
                    ErrorHandling.Handle(new($"Failed to use {RND.URANDOM}", ex, Constants.CRYPTO_ERROR_SOURCE));
                    if (RND.RequireDevUrandom)
                        throw await CryptographicException.FromAsync($"{RND.URANDOM} required and available, but failed", ex).DynamicContext();
                    Logging.WriteWarning($"Failed to use {RND.URANDOM} as random byte source (disabling and fallback to RandomNumberGenerator)");
                    UseDevUrandom = false;
                }
            }
            // Use the default .NET RandomNumberGenerator
            if (RND.RequireDevUrandom)
                throw await CryptographicException.FromAsync($"{RND.URANDOM} required, but not available or disabled", new InvalidOperationException()).DynamicContext();
            await RandomStream.Instance.CopyToAsync(RandomData, CancelToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            RandomData.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            await RandomData.DisposeAsync().DynamicContext();
        }
    }
}
