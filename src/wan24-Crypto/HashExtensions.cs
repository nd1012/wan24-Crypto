namespace wan24.Crypto
{
    /// <summary>
    /// Hash extensions
    /// </summary>
    public static class HashExtensions
    {
        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(this Span<byte> data, CryptoOptions? options = null) => ((ReadOnlySpan<byte>)data).Hash(options);

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static Span<byte> Hash(this Span<byte> data, Span<byte> outputBuffer, CryptoOptions? options = null) => ((ReadOnlySpan<byte>)data).Hash(outputBuffer, options);

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(this ReadOnlyMemory<byte> data, CryptoOptions? options = null) => data.Span.Hash(options);

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static Span<byte> Hash(this ReadOnlyMemory<byte> data, Span<byte> outputBuffer, CryptoOptions? options = null) => data.Span.Hash(outputBuffer, options);

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(this Memory<byte> data, CryptoOptions? options = null) => data.Span.Hash(options);

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static Span<byte> Hash(this Memory<byte> data, Span<byte> outputBuffer, CryptoOptions? options = null) => data.Span.Hash(outputBuffer, options);
    }
}
