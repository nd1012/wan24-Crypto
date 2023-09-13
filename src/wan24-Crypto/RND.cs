using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Random generators
    /// </summary>
    public static class RND
    {
        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        public static RNG_Delegate FillBytes { get; set; } = DefaultRng;

        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        public static RNGAsync_Delegate FillBytesAsync { get; set; } = DefaultRngAsync;

        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="count">Number of random bytes to generate</param>
        /// <returns>Random bytes</returns>
        public static byte[] GetBytes(int count)
        {
            byte[] res = new byte[count];
            FillBytes(res);
            return res;
        }

        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="count">Number of random bytes to generate</param>
        /// <returns>Random bytes</returns>
        public static async Task<byte[]> GetBytesAsync(int count)
        {
            byte[] res = new byte[count];
            await FillBytesAsync(res).DynamicContext();
            return res;
        }

        /// <summary>
        /// Default RNG
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public static void DefaultRng(Span<byte> buffer) => RandomNumberGenerator.Fill(buffer);

        /// <summary>
        /// Default RNG
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public static Task DefaultRngAsync(Memory<byte> buffer)
        {
            RandomNumberGenerator.Fill(buffer.Span);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Delegate for a random generator
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public delegate void RNG_Delegate(Span<byte> buffer);

        /// <summary>
        /// Delegate for a random generator
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public delegate Task RNGAsync_Delegate(Memory<byte> buffer);
    }
}
