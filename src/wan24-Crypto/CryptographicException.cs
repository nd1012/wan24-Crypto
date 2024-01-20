using System.Security.Cryptography;
using wan24.Core;

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
        /// Constructor
        /// </summary>
        /// <param name="noDelay">No delay?</param>
        public CryptographicException(bool noDelay) : base()
        {
            if (!noDelay) DoDelay();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="noDelay">No delay?</param>
        /// <param name="message">Message</param>
        public CryptographicException(bool noDelay, string? message) : base(message)
        {
            if (!noDelay) DoDelay();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="noDelay">No delay?</param>
        /// <param name="message">Message</param>
        /// <param name="inner">Inner exception</param>
        public CryptographicException(bool noDelay, string? message, Exception inner) : base(message, inner)
        {
            if (!noDelay) DoDelay();
        }

        /// <summary>
        /// Delay
        /// </summary>
        public static TimeSpan? Delay { get; set; } = TimeSpan.FromMilliseconds(20);

        /// <summary>
        /// Create with an inner exception
        /// </summary>
        /// <param name="inner">Inner exception</param>
        /// <returns>Exception</returns>
        public static CryptographicException From(Exception inner)
        {
            CryptographicException res = new(inner.Message, inner);
            ErrorHandling.Handle(new(res, Constants.CRYPTO_ERROR_SOURCE));
            return res;
        }

        /// <summary>
        /// Create with an inner exception
        /// </summary>
        /// <param name="message">Overriding message</param>
        /// <param name="inner">Inner exception</param>
        /// <returns>Exception</returns>
        public static CryptographicException From(string message, Exception inner)
        {
            CryptographicException res = new($"{message}: {inner.Message}", inner);
            ErrorHandling.Handle(new(res, Constants.CRYPTO_ERROR_SOURCE));
            return res;
        }

        /// <summary>
        /// Create with an inner exception
        /// </summary>
        /// <param name="inner">Inner exception</param>
        /// <returns>Exception</returns>
        public static async Task<CryptographicException> FromAsync(Exception inner)
        {
            CryptographicException res = new(noDelay: true, message: null, inner);
            ErrorHandling.Handle(new(res, Constants.CRYPTO_ERROR_SOURCE));
            if (Delay is not null) await Task.Delay(RandomNumberGenerator.GetInt32((int)Delay.Value.TotalMilliseconds));
            return res;
        }

        /// <summary>
        /// Create with an inner exception
        /// </summary>
        /// <param name="message">Overriding message</param>
        /// <param name="inner">Inner exception</param>
        /// <returns>Exception</returns>
        public static async Task<CryptographicException> FromAsync(string message, Exception inner)
        {
            CryptographicException res = new(noDelay: true, message, inner);
            ErrorHandling.Handle(new(res, Constants.CRYPTO_ERROR_SOURCE));
            if (Delay is not null) await Task.Delay(RandomNumberGenerator.GetInt32((int)Delay.Value.TotalMilliseconds));
            return res;
        }

        /// <summary>
        /// Delay for a random time
        /// </summary>
        private static void DoDelay()
        {
            if (!Delay.HasValue) return;
            Thread.Sleep(RandomNumberGenerator.GetInt32((int)Delay.Value.TotalMilliseconds));
        }
    }
}
