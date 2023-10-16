using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <c>/dev/urandom</c> RNG
    /// </summary>
    public sealed class DevURandomRng : SeedableRngBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public DevURandomRng() : base() { }

        /// <inheritdoc/>
        public override void AddSeed(ReadOnlySpan<byte> seed) => RND.AddURandomSeed(seed);

        /// <inheritdoc/>
        public override Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default) => RND.AddURandomSeedAsync(seed, cancellationToken);

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            if (RND.DevURandomPool is null)
            {
                using Stream urandom = RND.GetDevUrandom();
                if (urandom.Read(buffer) != buffer.Length)
                    throw new IOException($"Failed to read {buffer.Length} byte from /dev/urandom");
            }
            else
            {
                using RentedObject<Stream> urandom = new(RND.DevURandomPool);
                if (urandom.Object.Read(buffer) != buffer.Length)
                    throw new IOException($"Failed to read {buffer.Length} byte from /dev/urandom");
            }
            return buffer;
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (RND.DevURandomPool is null)
            {
                Stream urandom = RND.GetDevUrandom();
                await using (urandom.DynamicContext())
                    if (await urandom.ReadAsync(buffer, cancellationToken).DynamicContext() != buffer.Length)
                        throw new IOException($"Failed to read {buffer.Length} byte from /dev/urandom");
            }
            else
            {
                using RentedObject<Stream> urandom = new(RND.DevURandomPool);
                if (await urandom.Object.ReadAsync(buffer, cancellationToken).DynamicContext() != buffer.Length)
                    throw new IOException($"Failed to read {buffer.Length} byte from /dev/urandom");
            }
            return buffer;
        }
    }
}
