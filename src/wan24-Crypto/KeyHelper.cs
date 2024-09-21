using System.Text;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Key helper
    /// </summary>
    public static class KeyHelper
    {
        /// <summary>
        /// RNG to use
        /// </summary>
        public static IRng RNG { get; set; } = Rng.Instance;

        /// <summary>
        /// Create an (almost) unique key
        /// </summary>
        /// <param name="len">Length in bytes (at last 8 bytes required)</param>
        /// <returns>Key</returns>
        public static byte[] CreateUniqueKey(in int len)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(len, other: sizeof(int) << 1, nameof(len));
            byte[] res = new byte[len];
            CreateUniqueKey(res);
            return res;
        }

        /// <summary>
        /// Create an (almost) unique key
        /// </summary>
        /// <param name="buffer">Buffer (at last 8 bytes required)</param>
        public static void CreateUniqueKey(in Span<byte> buffer)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(buffer.Length, other: sizeof(int) << 1, nameof(buffer));
            int randomLen = buffer.Length - sizeof(int);
            RNG.FillBytes(buffer[..randomLen]);
            UnixTime.Now.EpochSeconds.GetBytes(buffer[randomLen..]);
        }

        /// <summary>
        /// Create an (almost) unique key
        /// </summary>
        /// <param name="len">Length in bytes (at last 8 bytes required)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public static async Task<byte[]> CreateUniqueKeyAsync(int len, CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(len, other: sizeof(int) << 1, nameof(len));
            byte[] res = new byte[len];
            await CreateUniqueKeyAsync(res, cancellationToken).DynamicContext();
            return res;
        }

        /// <summary>
        /// Create an (almost) unique key
        /// </summary>
        /// <param name="buffer">Buffer (at last 8 bytes required)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static async Task CreateUniqueKeyAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(buffer.Length, other: sizeof(int) << 1, nameof(buffer));
            int randomLen = buffer.Length - sizeof(int);
            await RNG.FillBytesAsync(buffer[..randomLen], cancellationToken).DynamicContext();
            UnixTime.Now.EpochSeconds.GetBytes(buffer.Span[randomLen..]);
        }
    }
}
