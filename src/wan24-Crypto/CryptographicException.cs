using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// Thrown on any cryptographic problem
    /// </summary>
    [Serializable]
    public sealed class CryptographicException : Exception
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public CryptographicException() : base() => DoDelay();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="message">Message</param>
        public CryptographicException(string? message) : base(message) => DoDelay();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="message">Message</param>
        /// <param name="inner">Inner exception</param>
        public CryptographicException(string? message, Exception inner) : base(message, inner) => DoDelay();

        /// <summary>
        /// Delay
        /// </summary>
        public static TimeSpan? Delay { get; set; } = TimeSpan.FromMilliseconds(100);

        /// <summary>
        /// Create with an inner exception
        /// </summary>
        /// <param name="inner">Inner exception</param>
        /// <returns>Exception</returns>
        public static CryptographicException From(Exception inner) => new(inner.Message, inner);

        /// <summary>
        /// Create with an inner exception
        /// </summary>
        /// <param name="message">Overriding message</param>
        /// <param name="inner">Inner exception</param>
        /// <returns>Exception</returns>
        public static CryptographicException From(string message, Exception inner) => new($"{message}: {inner.Message}", inner);

        /// <summary>
        /// Delay for a random time
        /// </summary>
        private static void DoDelay()
        {
            if (Delay == null) return;
            Thread.Sleep(RandomNumberGenerator.GetInt32((int)Delay.Value.TotalMilliseconds));
        }
    }
}
