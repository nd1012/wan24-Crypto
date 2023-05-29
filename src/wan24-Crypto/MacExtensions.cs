namespace wan24.Crypto
{
    /// <summary>
    /// MAC extensions
    /// </summary>
    public static class MacExtensions
    {
        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this Span<byte> data, byte[] pwd, CryptoOptions? options = null) => ((ReadOnlySpan<byte>)data).Mac(pwd, options);

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static Span<byte> Mac(this Span<byte> data, byte[] pwd, Span<byte> outputBuffer, CryptoOptions? options = null)
            => ((ReadOnlySpan<byte>)data).Mac(pwd, outputBuffer, options);

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this ReadOnlyMemory<byte> data, byte[] pwd, CryptoOptions? options = null) => data.Span.Mac(pwd, options);

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static Span<byte> Mac(this ReadOnlyMemory<byte> data, byte[] pwd, Span<byte> outputBuffer, CryptoOptions? options = null) => data.Span.Mac(pwd, outputBuffer, options);

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this Memory<byte> data, byte[] pwd, CryptoOptions? options = null) => data.Span.Mac(pwd, options);

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static Span<byte> Mac(this Memory<byte> data, byte[] pwd, Span<byte> outputBuffer, CryptoOptions? options = null) => data.Span.Mac(pwd, outputBuffer, options);
    }
}
