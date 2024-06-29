using System.Collections.Frozen;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// RNG which uses backup RNGs on error
    /// </summary>
    public class BackupRng : RngBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rngs">RNGs</param>
        public BackupRng(params IRng[] rngs) : base()
        {
            if (rngs.Length < 1) throw new ArgumentOutOfRangeException(nameof(rngs));
            RNGs = rngs.ToFrozenSet();
        }

        /// <summary>
        /// RNGs
        /// </summary>
        public FrozenSet<IRng> RNGs { get; }

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            List<Exception> exceptions = [];
            foreach(IRng rng in RNGs)
                try
                {
                    rng.FillBytes(buffer);
                    return buffer;
                }
                catch(Exception ex)
                {
                    exceptions.Add(ex);
                }
            throw CryptographicException.From(new AggregateException("No RNG produced RND without an error", [.. exceptions]));
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            List<Exception> exceptions = [];
            foreach (IRng rng in RNGs)
                try
                {
                    await rng.FillBytesAsync(buffer, cancellationToken).DynamicContext();
                    return buffer;
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            throw CryptographicException.From(new AggregateException("No RNG produced RND without an error", [.. exceptions]));
        }
    }
}
