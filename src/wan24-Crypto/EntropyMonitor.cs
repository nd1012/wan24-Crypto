using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Entropy monitoring RNG (uses <see cref="EntropyHelper.CheckEntropy(in ReadOnlySpan{byte}, EntropyHelper.Algorithms?, in bool)"/>)
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="rng">Entropy monitored RNG</param>
    public class EntropyMonitor(in IRng rng) : RngBase()
    {
        /// <summary>
        /// Entropy monitored RNG
        /// </summary>
        public IRng RNG { get; } = rng;

        /// <summary>
        /// Entropy algorithms to use
        /// </summary>
        public EntropyHelper.Algorithms? Algorithms { get; init; }

        /// <summary>
        /// Max. number of retries to get RND with the required entropy (zero for no limit)
        /// </summary>
        public int MaxRetries { get; init; }

        /// <summary>
        /// Min. RND length required for monitoring
        /// </summary>
        public int MinRndlength { get; init; }

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            if (buffer.Length < 1) return buffer;
            for (int i = 0, len = MaxRetries < 1 ? int.MaxValue : MaxRetries; i < len; i++)
            {
                RNG.FillBytes(buffer);
                if (buffer.Length < MinRndlength || EntropyHelper.CheckEntropy(buffer, Algorithms)) return buffer;
            }
            throw CryptographicException.From("Failed to get RND with the required entropy", new InvalidDataException());
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length < 1) return buffer;
            for (int i = 0, len = MaxRetries < 1 ? int.MaxValue : MaxRetries; i < len; i++)
            {
                await RNG.FillBytesAsync(buffer, cancellationToken).DynamicContext();
                if (buffer.Length < MinRndlength || EntropyHelper.CheckEntropy(buffer.Span, Algorithms)) return buffer;
            }
            throw CryptographicException.From("Failed to get RND with the required entropy", new InvalidDataException());
        }
    }
}
