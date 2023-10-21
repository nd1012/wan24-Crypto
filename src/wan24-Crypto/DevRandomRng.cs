using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <c>/dev/random</c> RNG
    /// </summary>
    public sealed class DevRandomRng : SeedableRngBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public DevRandomRng() : base() { }

        /// <inheritdoc/>
        public override void AddSeed(ReadOnlySpan<byte> seed) => RND.AddDevRandomSeed(seed);

        /// <inheritdoc/>
        public override Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default) => RND.AddDevRandomSeedAsync(seed, cancellationToken);

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            DateTime started = DateTime.Now;
            if (RND.DevRandomPool is null)
            {
                using Stream random = RND.GetDevRandom();
                if (random.Read(buffer) != buffer.Length)
                    throw new IOException($"Failed to read {buffer.Length} byte from {RND.RANDOM}");
            }
            else
            {
                using RentedObject<Stream> random = new(RND.DevRandomPool);
                if (random.Object.Read(buffer) != buffer.Length)
                    throw new IOException($"Failed to read {buffer.Length} byte from {RND.RANDOM}");
            }
            if (DateTime.Now - started > TimeSpan.FromSeconds(10))
                Logging.WriteWarning(
                    $"{RND.RANDOM} doesn't get enough entropy for returning {buffer.Length} byte random data within 10 seconds (took {DateTime.Now - started} instead)"
                    );
            return buffer;
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            DateTime started = DateTime.Now;
            if (RND.DevRandomPool is null)
            {
                Stream random = RND.GetDevRandom();
                await using (random.DynamicContext())
                    if (await random.ReadAsync(buffer, cancellationToken).DynamicContext() != buffer.Length)
                        throw new IOException($"Failed to read {buffer.Length} byte from {RND.RANDOM}");
            }
            else
            {
                using RentedObject<Stream> random = new(RND.DevRandomPool);
                if (await random.Object.ReadAsync(buffer, cancellationToken).DynamicContext() != buffer.Length)
                    throw new IOException($"Failed to read {buffer.Length} byte from {RND.RANDOM}");
            }
            if (DateTime.Now - started > TimeSpan.FromSeconds(10))
                Logging.WriteWarning(
                    $"{RND.RANDOM} doesn't get enough entropy for returning {buffer.Length} byte random data within 10 seconds (took {DateTime.Now - started} instead)"
                    );
            return buffer;
        }
    }
}
