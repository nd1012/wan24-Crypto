using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// RNG seed timer seeds a seed consumer using random data from a given RNG
    /// </summary>
    public sealed class RngSeedTimer : TimedHostedServiceBase
    {
        /// <summary>
        /// RNG
        /// </summary>
        private readonly IRng RNG;
        /// <summary>
        /// Seed consumer
        /// </summary>
        private readonly ISeedConsumer? SeedConsumer;
        /// <summary>
        /// Seed buffer
        /// </summary>
        private readonly byte[] Seed;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rng">RNG</param>
        /// <param name="seed">Seed length in byte</param>
        /// <param name="interval">Interval in ms</param>
        /// <param name="seedConsumer">Seed consumer</param>
        public RngSeedTimer(in IRng rng, in int seed, in double interval, in ISeedConsumer? seedConsumer = null) : base(interval)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(seed, 1);
            RNG = rng;
            SeedConsumer = seedConsumer;
            Seed = new byte[seed];
        }

        /// <inheritdoc/>
        protected override async Task TimedWorkerAsync()
        {
            try
            {
                await RNG.FillBytesAsync(Seed, CancelToken).DynamicContext();
                if (SeedConsumer is null)
                {
                    await RND.AddSeedAsync(Seed, CancelToken).DynamicContext();
                }
                else
                {
                    await SeedConsumer.AddSeedAsync(Seed, CancelToken).DynamicContext();
                }
            }
            finally
            {
                Array.Clear(Seed);
            }
        }
    }
}
