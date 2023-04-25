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
        public static byte[] Hash(this Span<byte> data, CryptoOptions? options = null)
        {
            try
            {
                using MemoryStream ms = new();
                ms.Write(data);
                ms.Position = 0;
                return ms.Hash(options);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

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
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(this byte[] data, CryptoOptions? options = null) => data.AsSpan().Hash(options);
    }
}
