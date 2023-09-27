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
        /// URandom filename
        /// </summary>
        internal const string URANDOM = "/dev/urandom";

        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        internal static RNG_Delegate _FillBytes = DefaultRng;
        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        internal static RNGAsync_Delegate _FillBytesAsync = DefaultRngAsync;
        /// <summary>
        /// Has <c>/dev/urandom</c>?
        /// </summary>
        public static readonly bool HasDevUrandom;

        /// <summary>
        /// Constructor
        /// </summary>
        static RND() => UseDevUrandom = HasDevUrandom = !ENV.IsBrowserApp && !ENV.IsWindows && File.Exists(URANDOM);

        /// <summary>
        /// Random data generator service
        /// </summary>
        public static RandomDataGenerator? Generator { get; set; }

        /// <summary>
        /// Use <c>/dev/urandom</c>, if available?
        /// </summary>
        [CliConfig]
        public static bool UseDevUrandom { get; set; }

        /// <summary>
        /// Require <c>/dev/urandom</c> (will throw, if not available)?
        /// </summary>
        [CliConfig]
        public static bool RequireDevUrandom { get; set; }

        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        public static RNG_Delegate FillBytes
        {
            get => Generator is null ? _FillBytes : GeneratorRng;
            set => _FillBytes = value;
        }

        /// <summary>
        /// Fill a buffer with random bytes
        /// </summary>
        public static RNGAsync_Delegate FillBytesAsync
        {
            get => Generator is null ? _FillBytesAsync : GeneratorRngAsync;
            set => _FillBytesAsync = value;
        }

        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="count">Number of random bytes to generate</param>
        /// <returns>Random bytes</returns>
        public static byte[] GetBytes(in int count)
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
        /// Default RNG (uses <c>/dev/urandom</c>, if possible; falls back to <see cref="RandomNumberGenerator"/>)
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public static void DefaultRng(Span<byte> buffer)
        {
            if (UseDevUrandom && HasDevUrandom)
                try
                {
                    using Stream urandom = GetDevUrandom();
                    if (urandom.Read(buffer) != buffer.Length)
                        throw new IOException("Failed to read random bytes");
                    return;
                }
                catch (Exception ex)
                {
                    ErrorHandling.Handle(new($"Failed to use {URANDOM}", ex, Constants.CRYPTO_ERROR_SOURCE));
                    if (RequireDevUrandom)
                        throw CryptographicException.From($"{URANDOM} required and available, but failed", ex);
                    Logging.WriteWarning($"Failed to use {URANDOM} as random byte source (disabling and fallback to RandomNumberGenerator)");
                    UseDevUrandom = false;
                }
            if (RequireDevUrandom) throw CryptographicException.From($"{URANDOM} required, but not available or disabled", new InvalidOperationException());
            RandomNumberGenerator.Fill(buffer);
        }

        /// <summary>
        /// Default RNG (uses <c>/dev/urandom</c>, if possible; falls back to <see cref="RandomNumberGenerator"/>)
        /// </summary>
        /// <param name="buffer">Buffer to fill with random material</param>
        public static async Task DefaultRngAsync(Memory<byte> buffer)
        {
            if (UseDevUrandom && HasDevUrandom)
                try
                {
                    Stream urandom = GetDevUrandom();
                    await using (urandom.DynamicContext())
                        if (await urandom.ReadAsync(buffer).DynamicContext() != buffer.Length)
                            throw new IOException("Failed to read random bytes");
                    return;
                }
                catch (Exception ex)
                {
                    ErrorHandling.Handle(new($"Failed to use {URANDOM}", ex, Constants.CRYPTO_ERROR_SOURCE));
                    if (RequireDevUrandom)
                        throw await CryptographicException.FromAsync($"{URANDOM} required and available, but failed", ex).DynamicContext();
                    Logging.WriteWarning($"Failed to use {URANDOM} as random byte source (disabling and fallback to RandomNumberGenerator)");
                    UseDevUrandom = false;
                }
            if (RequireDevUrandom)
                throw await CryptographicException.FromAsync($"{URANDOM} required, but not available or disabled", new InvalidOperationException()).DynamicContext();
            RandomNumberGenerator.Fill(buffer.Span);
        }

        /// <summary>
        /// Get a <c>/dev/urandom</c> stream
        /// </summary>
        /// <returns><c>/dev/urandom</c> stream</returns>
        public static Stream GetDevUrandom() => new FileStream(URANDOM, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

        /// <summary>
        /// Generator RNG
        /// </summary>
        /// <param name="buffer">Buffer</param>
        private static void GeneratorRng(Span<byte> buffer) => Generator!.FillBytes(buffer);

        /// <summary>
        /// Generator RNG
        /// </summary>
        /// <param name="buffer">Buffer</param>
        private static async Task GeneratorRngAsync(Memory<byte> buffer) => await Generator!.FillBytesAsync(buffer).DynamicContext();

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
