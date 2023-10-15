﻿using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// The online seed timer applies https received seeds in an interval (requests the first seed during startup)
    /// </summary>
    public class RngOnlineSeedTimer : TimedHostedServiceBase
    {
        /// <summary>
        /// Default re-seed interval in ms
        /// </summary>
        public const double DEFAULT_INTERVAL = 28_800_000;
        /// <summary>
        /// Default URI (private and free service without any warranty!)
        /// </summary>
        public const string DEFAULT_URI = "https://rng.wan24.de/seed/bin?len=256";
        /// <summary>
        /// Default seed length in byte
        /// </summary>
        public const int DEFAULT_SEED_LENGTH = 256;

        /// <summary>
        /// http client
        /// </summary>
        protected readonly HttpClient Http;
        /// <summary>
        /// Seed
        /// </summary>
        protected readonly byte[] Seed;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="interval">Seed request interval in ms (default is 8 hours)</param>
        /// <param name="rng">RNG to seed (if <see langword="null"/>, <see cref="RND"/> will be seeded)</param>
        /// <param name="uri">URI to <c>GET</c> the seed (byte sequence) from</param>
        /// <param name="length">Seed length in byte to receive from the given URI</param>
        /// <param name="http">http client to use (will be disposed!)</param>
        public RngOnlineSeedTimer(
            in double interval = DEFAULT_INTERVAL,
            in ISeedableRng? rng = null,
            in string uri = DEFAULT_URI,
            in int length = DEFAULT_SEED_LENGTH,
            in HttpClient? http = null
            )
            : base(interval)
        {
            if (length < 1) throw new ArgumentOutOfRangeException(nameof(length));
            URI = new Uri(uri).ToString();
            Seed = new byte[length];
            Http = http ?? new HttpClient();
            RNG = rng;
        }

        /// <summary>
        /// RNG to seed (if <see langword="null"/>, <see cref="RND"/> will be seeded)
        /// </summary>
        public ISeedableRng? RNG { get; }

        /// <summary>
        /// URI to get the seed from (without trailing slash)
        /// </summary>
        public string URI { get; }

        /// <summary>
        /// Seed length in byte
        /// </summary>
        public int SeedLength => Seed.Length;

        /// <summary>
        /// XOR <see cref="RND"/> generated bytes to the received seeds?
        /// </summary>
        public bool XorRnd { get; set; } = true;

        /// <inheritdoc/>
        protected sealed override Task TimedWorkerAsync() => TimedWorkerAsync(CancelToken);

        /// <summary>
        /// Timed worker
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If seeded successfully</returns>
        protected virtual async Task<bool> TimedWorkerAsync(CancellationToken cancellationToken)
        {
            try
            {
                int red = await RequestSeedAsync(cancellationToken).DynamicContext();
                if (red < 1) return false;
                if (XorRnd)
                {
                    using RentedArrayStructSimple<byte> buffer = new(red, clean: false)
                    {
                        Clear = true
                    };
                    await RND.FillBytesAsync(buffer.Memory).DynamicContext();
                    Seed.Xor(buffer.Span);
                }
                if (RNG is null) await RND.AddSeedAsync(Seed.AsMemory(0, red), cancellationToken).DynamicContext();
                else await RNG.AddSeedAsync(Seed.AsMemory(0, red), cancellationToken).DynamicContext();
                return true;
            }
            catch (Exception ex)
            {
                if (ServiceTask is null) throw;
                ErrorHandling.Handle(new($"Failed to get seed from \"{URI}\"", ex, Constants.CRYPTO_ERROR_SOURCE));
                return false;
            }
            finally
            {
                Seed.Clear();
            }
        }

        /// <summary>
        /// Request fresh seed online (need to be written to <see cref="Seed"/>)
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Number of received seed bytes</returns>
        protected virtual async Task<int> RequestSeedAsync(CancellationToken cancellationToken)
        {
            int red;
            Stream qrngSeeded = await Http.GetStreamAsync(URI, cancellationToken).DynamicContext();
            await using (qrngSeeded.DynamicContext()) red = await qrngSeeded.ReadAsync(Seed, cancellationToken).DynamicContext();
            if (red == 0)
            {
                Logging.WriteWarning($"{GetType()} got no seed from \"{URI}\"");
                return 0;
            }
            Logging.WriteDebug($"{GetType()} got {red} byte seed from \"{URI}\"");
            if (red != Seed.Length)
                Logging.WriteWarning($"{GetType()} expected {Seed.Length} byte seed, but got only {red} byte instead from \"{URI}\"");
            return red;
        }

        /// <inheritdoc/>
        protected override async Task BeforeStartAsync(CancellationToken cancellationToken)
        {
            await base.BeforeStartAsync(cancellationToken).DynamicContext();
            if (!await TimedWorkerAsync(cancellationToken).DynamicContext())
                throw await CryptographicException.FromAsync($"Initial seeding of RNG online seed timer ({GetType()}) {GUID} (\"{Name}\") failed", new IOException());
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            Http.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Http.Dispose();
        }
    }
}