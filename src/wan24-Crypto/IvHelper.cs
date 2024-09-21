using System.Text;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// IV helper
    /// </summary>
    public static class IvHelper
    {
        /// <summary>
        /// RNG to use
        /// </summary>
        public static IRng RNG { get; set; } = Rng.Instance;

        /// <summary>
        /// Create (almost) unique and indeterministic IV bytes
        /// </summary>
        /// <param name="len">Length in bytes (at last 8 bytes required)</param>
        /// <returns>IV bytes</returns>
        public static byte[] CreateUniqueIv(in int len)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(len, other: sizeof(int) << 1, nameof(len));
            byte[] res = new byte[len];
            CreateUniqueIv(res);
            return res;
        }

        /// <summary>
        /// Create (almost) unique and indeterministic IV bytes
        /// </summary>
        /// <param name="buffer">Buffer (at last 8 bytes required)</param>
        public static void CreateUniqueIv(in Span<byte> buffer)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(buffer.Length, other: sizeof(int) << 1, nameof(buffer));
            int rndLen = buffer.Length - sizeof(int);
            RNG.FillBytes(buffer[rndLen..]);
            UnixTime.Now.EpochSeconds.GetBytes(buffer[rndLen..]).ConvertEndian();
        }

        /// <summary>
        /// Create (almost) unique and indeterministic IV bytes
        /// </summary>
        /// <param name="len">Length in bytes (at last 8 bytes required)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>IV bytes</returns>
        public static async Task<byte[]> CreateUniqueIvAsync(int len, CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(len, other: sizeof(int) << 1, nameof(len));
            byte[] res = new byte[len];
            await CreateUniqueIvAsync(res, cancellationToken).DynamicContext();
            return res;
        }

        /// <summary>
        /// Create (almost) unique and indeterministic IV bytes
        /// </summary>
        /// <param name="buffer">Buffer (at last 8 bytes required)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static async Task CreateUniqueIvAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(buffer.Length, other: sizeof(int) << 1, nameof(buffer));
            int rndLen = buffer.Length - sizeof(int);
            await RNG.FillBytesAsync(buffer[rndLen..], cancellationToken).DynamicContext();
            UnixTime.Now.EpochSeconds.GetBytes(buffer.Span[rndLen..]).ConvertEndian();
        }
    }
}
