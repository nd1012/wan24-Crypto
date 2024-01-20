using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Random data generator (uses <c>/dev/random</c>, if possible; defaults to <see cref="RandomNumberGenerator"/>)
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="capacity">Capacity in bytes</param>
    public class RandomDataGenerator(in int capacity) : HostedServiceBase(), ISeedableRng
    {
        /// <summary>
        /// Random data
        /// </summary>
        protected readonly BlockingBufferStream RandomData = new(capacity, clear: true);
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
        /// <param name="useRnd">Use the <see cref="RND"/> methods?</param>
        public RandomDataGenerator(in int capacity, in bool useRnd) : this(capacity) => UseRng = useRnd;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Capacity in bytes</param>
        /// <param name="rng">RNG</param>
        /// <param name="rngAsync">RNG</param>
        public RandomDataGenerator(in int capacity, in RND.RNG_Delegate rng, in RND.RNGAsync_Delegate rngAsync) : this(capacity, useRnd: true)
        {
            Rng = rng;
            RngAsync = rngAsync;
        }

        /// <summary>
        /// Use fallback methods?
        /// </summary>
        public bool UseFallback { get; set; } = true;

        /// <summary>
        /// Use <c>/dev/random</c>, if available?
        /// </summary>
        public bool UseDevRandom { get; set; } = RND.UseDevRandom;

        /// <inheritdoc/>
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
            else
            {
                RandomData.ReadExactly(res);
            }
            return res;
        }

        /// <inheritdoc/>
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
            else
            {
                await RandomData.ReadExactlyAsync(res, cancellationToken).DynamicContext();
            }
            return res;
        }

        /// <inheritdoc/>
        public Span<byte> FillBytes(in Span<byte> buffer)
        {
            EnsureUndisposed();
            if (!IsRunning) throw new InvalidOperationException();
            if (UseFallback)
            {
                int red = RandomData.TryRead(buffer);
                if (red != buffer.Length) Rng(buffer[red..]);
            }
            else
            {
                RandomData.ReadExactly(buffer);
            }
            return buffer;
        }

        /// <inheritdoc/>
        public async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (!IsRunning) throw new InvalidOperationException();
            if (UseFallback)
            {
                int red = RandomData.TryRead(buffer.Span);
                if (red != buffer.Length) await RngAsync(buffer[red..]).DynamicContext();
            }
            else
            {
                await RandomData.ReadExactlyAsync(buffer, cancellationToken).DynamicContext();
            }
            return buffer;
        }

        /// <inheritdoc/>
        public virtual void AddSeed(ReadOnlySpan<byte> seed)
        {
            if (RND.SeedConsumer is not null && RND.SeedConsumer != this) RND.SeedConsumer.AddSeed(seed);
            else if (RND.Generator is ISeedableRng seedableGenerator && seedableGenerator != this) seedableGenerator.AddSeed(seed);
            else RND.AddDevRandomSeed(seed);
        }

        /// <inheritdoc/>
        public virtual Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
        {
            if (RND.SeedConsumer is not null && RND.SeedConsumer != this) return RND.SeedConsumer.AddSeedAsync(seed, cancellationToken);
            if (RND.Generator is ISeedableRng seedableGenerator && seedableGenerator != this) return seedableGenerator.AddSeedAsync(seed, cancellationToken);
            return RND.AddDevRandomSeedAsync(seed, cancellationToken);
        }

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
                while (EnsureNotCanceled(throwOnCancellation: false))
                {
                    await FillAsync(buffer.Memory).DynamicContext();
                    if (EnsureNotCanceled(throwOnCancellation: false))
                        await writeTask.AsTask().WaitAsync(CancelToken).DynamicContext();
                    if (EnsureNotCanceled(throwOnCancellation: false))
                        writeTask = RandomData.WriteAsync(buffer.Memory, CancelToken);
                }
                await writeTask.AsTask().WaitAsync(CancelToken).DynamicContext();
                return;
            }
            else if(UseDevRandom && RND.HasDevRandom)
            {
                // Use /dev/random
                try
                {
                    if (RND.DevRandomPool is null)
                    {
                        Stream random = RND.GetDevRandom();
                        await using (random.DynamicContext()) await random.CopyToAsync(RandomData, CancelToken).DynamicContext();
                    }
                    else
                    {
                        using RentedObject<Stream> random = new(RND.DevRandomPool);
                        await random.Object.CopyToAsync(RandomData, CancelToken).DynamicContext();
                    }
                    return;
                }
                catch(Exception ex)
                {
                    ErrorHandling.Handle(new($"Failed to use {RND.RANDOM}", ex, Constants.CRYPTO_ERROR_SOURCE));
                    if (RND.RequireDevRandom)
                        throw await CryptographicException.FromAsync($"{RND.RANDOM} required and available, but failed", ex).DynamicContext();
                    Logging.WriteWarning($"Failed to use {RND.RANDOM} as random byte source (disabling and fallback to {nameof(RandomNumberGenerator)})");
                    UseDevRandom = false;
                }
            }
            // Use the default .NET RandomNumberGenerator
            if (RND.RequireDevRandom)
                throw await CryptographicException.FromAsync($"{RND.RANDOM} required, but not available or disabled", new InvalidOperationException()).DynamicContext();
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
