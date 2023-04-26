using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto extensions
    /// </summary>
    public static class CryptoExtensions
    {
        /// <summary>
        /// Add random padding bytes
        /// </summary>
        /// <typeparam name="T">Stream type</typeparam>
        /// <param name="stream">Stream</param>
        /// <param name="blockSize">Block size in bytes</param>
        /// <param name="written">Number of written bytes</param>
        /// <returns>Stream</returns>
        public static T AddPadding<T>(this T stream, int blockSize, long? written = null) where T : Stream
        {
            try
            {
                if (blockSize < 1) throw new ArgumentOutOfRangeException(nameof(blockSize));
                if (written != null && written < 0) throw new ArgumentOutOfRangeException(nameof(written));
                stream.Write(RandomNumberGenerator.GetBytes(blockSize - (int)((written ?? stream.Length) % blockSize)));
                return stream;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Add random padding bytes
        /// </summary>
        /// <typeparam name="T">Stream type</typeparam>
        /// <param name="stream">Stream</param>
        /// <param name="blockSize">Block size in bytes</param>
        /// <param name="written">Number of written bytes</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static async Task AddPaddingAsync<T>(this T stream, int blockSize, long? written = null, CancellationToken cancellationToken = default) where T : Stream
        {
            try
            {
                if (blockSize < 1) throw new ArgumentOutOfRangeException(nameof(blockSize));
                if (written != null && written < 0) throw new ArgumentOutOfRangeException(nameof(written));
                await stream.WriteAsync(RandomNumberGenerator.GetBytes(blockSize - (int)((written ?? stream.Length) % blockSize)), cancellationToken).DynamicContext();
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
        /// Validate a MAC
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="mac">MAC</param>
        /// <param name="pwd">Password</param>
        /// <param name="resetPosition">Reset the original stream position?</param>
        /// <param name="options">Options</param>
        /// <returns>If the MAC is valid</returns>
        public static bool ValidateMac(this Stream stream, byte[] mac, byte[] pwd, bool resetPosition = true, CryptoOptions? options = null)
        {
            try
            {
                if (!stream.CanRead) throw new NotSupportedException();
                if (resetPosition && !stream.CanSeek) throw new InvalidOperationException();
                long pos = resetPosition ? stream.Position : 0;
                try
                {
                    return mac.AsSpan().SlowCompare(stream.Mac(pwd, options));
                }
                finally
                {
                    if (resetPosition) stream.Position = pos;
                }
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
        /// Validate a MAC
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="mac">MAC</param>
        /// <param name="pwd">Password</param>
        /// <param name="resetPosition">Reset the original stream position?</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the MAC is valid</returns>
        public static async Task<bool> ValidateMacAsync(
            this Stream stream,
            byte[] mac,
            byte[] pwd,
            bool resetPosition = true,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
        {
            try
            {
                if (!stream.CanRead) throw new NotSupportedException();
                if (resetPosition && !stream.CanSeek) throw new InvalidOperationException();
                long pos = resetPosition ? stream.Position : 0;
                try
                {
                    byte[] mac2 = await stream.MacAsync(pwd, options, cancellationToken).DynamicContext();
                    return mac.AsSpan().SlowCompare(mac2);
                }
                finally
                {
                    if (resetPosition) stream.Position = pos;
                }
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
    }
}
