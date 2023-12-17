using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Random generators
    /// </summary>
    public static class RND
    {
        /// <summary>
        /// Random filename
        /// </summary>
        public const string RANDOM = "/dev/random";// https://www.2uo.de/myths-about-urandom/

        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        internal static RNG_Delegate _FillBytes = DefaultRng;
        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        internal static RNGAsync_Delegate _FillBytesAsync = DefaultRngAsync;
        /// <summary>
        /// Random seeder
        /// </summary>
        private static readonly Stream? RandomSeeder;
        /// <summary>
        /// Has <c>/dev/random</c>?
        /// </summary>
        public static readonly bool HasDevRandom;

        /// <summary>
        /// Constructor
        /// </summary>
        static RND()
        {
            HasDevRandom = !ENV.IsBrowserApp && !ENV.IsWindows && File.Exists(RANDOM);
            RandomSeeder = HasDevRandom
                ? new SynchronizedStream(new FileStream(RANDOM, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                : null;
        }

        /// <summary>
        /// Random data generator
        /// </summary>
        public static IRng? Generator { get; set; }

        /// <summary>
        /// RNG seed consumer
        /// </summary>
        public static ISeedConsumer? SeedConsumer { get; set; }

        /// <summary>
        /// Use <c>/dev/random</c>, if available?
        /// </summary>
        [CliConfig]
        public static bool UseDevRandom { get; set; }

        /// <summary>
        /// Require <c>/dev/random</c> (will throw, if not available)?
        /// </summary>
        [CliConfig]
        public static bool RequireDevRandom { get; set; }

        /// <summary>
        /// <c>/dev/random</c> readable stream pool
        /// </summary>
        public static DevRandomStreamPool? DevRandomPool { get; set; }

        /// <summary>
        /// Automatic RNG seeding flags
        /// </summary>
        [CliConfig]
        public static RngSeedingTypes AutoRngSeeding { get; set; }

        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        public static RNG_Delegate FillBytes
        {
            get => Generator is null ? _FillBytes : GeneratorRng;
            set => _FillBytes = value;
        }

        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        public static RNGAsync_Delegate FillBytesAsync
        {
            get => Generator is null ? _FillBytesAsync : GeneratorRngAsync;
            set => _FillBytesAsync = value;
        }

        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="count">Number of random bytes to generate</param>
        /// <returns>Random bytes</returns>
        public static byte[] GetBytes(in int count)
        {
            byte[] res = new byte[count];
            FillBytes(res);
            return res;
        }

        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="count">Number of random bytes to generate</param>
        /// <returns>Random bytes</returns>
        public static async Task<byte[]> GetBytesAsync(int count)
        {
            byte[] res = new byte[count];
            await FillBytesAsync(res).DynamicContext();
            return res;
        }

        /// <summary>
        /// Add seed to the RNG
        /// </summary>
        /// <param name="seed">Seed</param>
        public static void AddSeed(ReadOnlySpan<byte> seed)
        {
            if (SeedConsumer is not null) SeedConsumer.AddSeed(seed);
            else if (Generator is ISeedableRng seedableRng) seedableRng.AddSeed(seed);
            else AddDevRandomSeed(seed);
        }

        /// <summary>
        /// Add seed to the RNG
        /// </summary>
        /// <param name="seed">Seed</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
            => SeedConsumer?.AddSeedAsync(seed, cancellationToken) ??
                (Generator as ISeedableRng)?.AddSeedAsync(seed, cancellationToken) ??
                AddDevRandomSeedAsync(seed, cancellationToken);

        /// <summary>
        /// Add seed to <c>/dev/random</c> (if available)
        /// </summary>
        /// <param name="seed">Seed</param>
        public static void AddDevRandomSeed(ReadOnlySpan<byte> seed) => RandomSeeder?.Write(seed);

        /// <summary>
        /// Add seed to <c>/dev/random</c> (if available)
        /// </summary>
        /// <param name="seed">Seed</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static async Task AddDevRandomSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
        {
            if (RandomSeeder is not null) await RandomSeeder.WriteAsync(seed, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Default RNG (uses <c>/dev/random</c>, if possible; falls back to <see cref="RandomNumberGenerator"/>)
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public static void DefaultRng(Span<byte> buffer)
        {
            if (UseDevRandom && HasDevRandom)
                try
                {
                    DateTime started = DateTime.Now;
                    if (DevRandomPool is null)
                    {
                        using Stream random = GetDevRandom();
                        random.ReadExactly(buffer);
                    }
                    else
                    {
                        using RentedObject<Stream> random = new(DevRandomPool);
                        random.Object.ReadExactly(buffer);
                    }
                    if (DateTime.Now - started > TimeSpan.FromSeconds(10))
                        Logging.WriteWarning(
                            $"{RANDOM} doesn't get enough entropy for returning {buffer.Length} byte random data within 10 seconds (took {DateTime.Now - started} instead)"
                            );
                    return;
                }
                catch (Exception ex)
                {
                    ErrorHandling.Handle(new($"Failed to use {RANDOM}", ex, Constants.CRYPTO_ERROR_SOURCE));
                    if (RequireDevRandom)
                        throw CryptographicException.From($"{RANDOM} required and available, but failed", ex);
                    Logging.WriteWarning($"Failed to use {RANDOM} as random byte source (disabling and fallback to RandomNumberGenerator)");
                    UseDevRandom = false;
                }
            if (RequireDevRandom) throw CryptographicException.From($"{RANDOM} required, but not available or disabled", new InvalidOperationException());
            RandomNumberGenerator.Fill(buffer);
        }

        /// <summary>
        /// Default RNG (uses <c>/dev/random</c>, if possible; falls back to <see cref="RandomNumberGenerator"/>)
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public static async Task DefaultRngAsync(Memory<byte> buffer)
        {
            if (UseDevRandom && HasDevRandom)
                try
                {
                    DateTime started = DateTime.Now;
                    if (DevRandomPool is null)
                    {
                        Stream random = GetDevRandom();
                        await using (random.DynamicContext())
                            await random.ReadExactlyAsync(buffer).DynamicContext();
                    }
                    else
                    {
                        using RentedObject<Stream> random = new(DevRandomPool);
                        await random.Object.ReadExactlyAsync(buffer).DynamicContext();
                    }
                    if (DateTime.Now - started > TimeSpan.FromSeconds(10))
                        Logging.WriteWarning(
                            $"{RANDOM} doesn't get enough entropy for returning {buffer.Length} byte random data within 10 seconds (took {DateTime.Now - started} instead)"
                            );
                    return;
                }
                catch (Exception ex)
                {
                    ErrorHandling.Handle(new($"Failed to use {RANDOM}", ex, Constants.CRYPTO_ERROR_SOURCE));
                    if (RequireDevRandom)
                        throw await CryptographicException.FromAsync($"{RANDOM} required and available, but failed", ex).DynamicContext();
                    Logging.WriteWarning($"Failed to use {RANDOM} as random byte source (disabling and fallback to RandomNumberGenerator)");
                    UseDevRandom = false;
                }
            if (RequireDevRandom)
                throw await CryptographicException.FromAsync($"{RANDOM} required, but not available or disabled", new InvalidOperationException()).DynamicContext();
            RandomNumberGenerator.Fill(buffer.Span);
        }

        /// <summary>
        /// Get a <c>/dev/random</c> stream
        /// </summary>
        /// <returns><c>/dev/random</c> stream</returns>
        public static Stream GetDevRandom() => new FileStream(RANDOM, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

        /// <summary>
        /// Generator RNG
        /// </summary>
        /// <param name="buffer">Buffer</param>
        private static void GeneratorRng(Span<byte> buffer) => Generator!.FillBytes(buffer);

        /// <summary>
        /// Generator RNG
        /// </summary>
        /// <param name="buffer">Buffer</param>
        private static async Task GeneratorRngAsync(Memory<byte> buffer) => await Generator!.FillBytesAsync(buffer).DynamicContext();

        /// <summary>
        /// Delegate for a random generator
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public delegate void RNG_Delegate(Span<byte> buffer);

        /// <summary>
        /// Delegate for a random generator
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public delegate Task RNGAsync_Delegate(Memory<byte> buffer);
    }
}
