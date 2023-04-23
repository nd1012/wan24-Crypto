using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// Thrown on any cryptographic problem
    /// </summary>
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
        public TimeSpan? Delay { get; set; } = TimeSpan.FromMilliseconds(100);

        private void DoDelay()
        {
            if (Delay == null) return;
            Thread.Sleep(RandomNumberGenerator.GetInt32((int)Delay.Value.TotalMilliseconds));
        }
    }
}
