using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a RNG
    /// </summary>
    public abstract class RngBase : IRng
    {
        /// <summary>
        /// Constructor
        /// </summary>
        protected RngBase() { }

        /// <inheritdoc/>
        public abstract Span<byte> FillBytes(in Span<byte> buffer);

        /// <inheritdoc/>
        public abstract Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);


        /// <inheritdoc/>
        public byte[] GetBytes(in int count)
        {
            byte[] res = new byte[count];
            FillBytes(res);
            return res;
        }

        /// <inheritdoc/>
        public async Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default)
        {
            byte[] res = new byte[count];
            await FillBytesAsync(res, cancellationToken).DynamicContext();
            return res;
        }
    }
}
