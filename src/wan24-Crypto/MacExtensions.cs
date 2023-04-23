﻿namespace wan24.Crypto
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
        public static byte[] Mac(this Span<byte> data, byte[] pwd, CryptoOptions? options = null)
        {
            try
            {
                using MemoryStream ms = new();
                ms.Write(data);
                ms.Position = 0;
                return ms.Mac(pwd, options);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new CryptographicException(ex.Message, ex);
            }
        }

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
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this byte[] data, byte[] pwd, CryptoOptions? options = null) => data.AsSpan().Mac(pwd, options);
    }
}
