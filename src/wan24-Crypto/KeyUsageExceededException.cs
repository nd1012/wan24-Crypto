namespace wan24.Crypto
{
    /// <summary>
    /// Thrown if a key usage limitation was exceeded
    /// </summary>
    [Serializable]
    public class KeyUsageExceededException : Exception
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public KeyUsageExceededException() : base() { }

        /// <summary>
        /// Constructor
        /// </summary>
        public KeyUsageExceededException(string? message) : base(message) { }

        /// <summary>
        /// Constructor
        /// </summary>
        public KeyUsageExceededException(string? message, Exception? inner) : base(message, inner) { }
    }
}
