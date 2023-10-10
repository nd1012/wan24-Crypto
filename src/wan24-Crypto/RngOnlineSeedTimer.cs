﻿using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// The online seed timer applies https received seeds in an interval (can be extended with a customized seed source URI; requests the first seed during startup)
    /// </summary>
    public class RngOnlineSeedTimer : TimedHostedServiceBase
    {
        /// <summary>
        /// Default URI (delivers 256 byte fresh CSRNG generated seed every 60 seconds, while fresh QRNG entrophy is being seeded to the used CSRNG about every 8 hours; NOTE: This is 
        /// a private and free service without any warranty, and for private use only!)
        /// </summary>
        public const string DEFAULT_URI = "https://qrng.wan24.de";
        /// <summary>
        /// Default seed length in bytes
        /// </summary>
        public const int DEFAULT_SEED_LENGTH = byte.MaxValue + 1;

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
        /// <param name="length">Seed length to receive from the given URI</param>
        /// <param name="http">http client to use (will be disposed!)</param>
        public RngOnlineSeedTimer(
            in double interval = 28_800_000, 
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
        /// Seed length in bytes
        /// </summary>
        public int SeedLength => Seed.Length;

        /// <inheritdoc/>
        protected sealed override Task TimedWorkerAsync() => TimedWorkerAsync(CancelToken);

        /// <inheritdoc/>
        protected virtual async Task TimedWorkerAsync(CancellationToken cancellationToken)
        {
            try
            {
                Stream qrngSeeded = await Http.GetStreamAsync(URI, cancellationToken).DynamicContext();
                await using (qrngSeeded.DynamicContext())
                {
                    int red = await qrngSeeded.ReadAsync(Seed, cancellationToken).DynamicContext();
                    if (red == 0)
                    {
                        Logging.WriteWarning($"{GetType()} got no seed from \"{URI}\"");
                        return;
                    }
                    Logging.WriteDebug($"{GetType()} got {red} byte seed from \"{URI}\"");
                    if (red != Seed.Length)
                        Logging.WriteWarning($"{GetType()} expected {Seed.Length} byte seed, but got only {red} byte instead from \"{URI}\"");
                    if (RNG is null) await RND.AddSeedAsync(Seed.AsMemory(0, red), cancellationToken).DynamicContext();
                    else await RNG.AddSeedAsync(Seed.AsMemory(0, red), cancellationToken).DynamicContext();
                }
            }
            catch (Exception ex)
            {
                if (ServiceTask is null) throw;
                ErrorHandling.Handle(new($"Failed to get seed from \"{URI}\"", ex, Constants.CRYPTO_ERROR_SOURCE));
            }
            finally
            {
                Seed.Clear();
            }
        }

        /// <inheritdoc/>
        protected override async Task BeforeStartAsync(CancellationToken cancellationToken)
        {
            await base.BeforeStartAsync(cancellationToken).DynamicContext();
            await TimedWorkerAsync(cancellationToken).DynamicContext();
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
