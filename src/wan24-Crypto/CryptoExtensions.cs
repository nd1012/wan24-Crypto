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
                ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);
                if (written is not null && written < 0) throw new ArgumentOutOfRangeException(nameof(written));
                int len = blockSize - (int)((written ?? stream.Length) % blockSize);
                if (len > Settings.StackAllocBorder)
                {
                    using RentedArrayRefStruct<byte> buffer = new(len, clean: false)
                    {
                        Clear = true
                    };
                    RND.FillBytes(buffer.Span);
                    stream.Write(buffer.Span);
                }
                else
                {
                    Span<byte> buffer = stackalloc byte[len];
                    RND.FillBytes(buffer);
                    stream.Write(buffer);
                }
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
                ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);
                if (written is not null && written < 0) throw new ArgumentOutOfRangeException(nameof(written));
                int len = blockSize - (int)((written ?? stream.Length) % blockSize);
                using RentedArrayStruct<byte> buffer = new(len, clean: false)
                {
                    Clear = true
                };
                RND.FillBytes(buffer.Span);
                await stream.WriteAsync(buffer.Memory, cancellationToken).DynamicContext();
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw await CryptographicException.FromAsync(ex);
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
                throw await CryptographicException.FromAsync(ex);
            }
        }

        /// <summary>
        /// Extend a key by additional keys
        /// </summary>
        /// <param name="key">Key (will be cleared!)</param>
        /// <param name="additionalKeys">Additional keys (will be cleared!)</param>
        /// <returns>Extended key</returns>
        public static byte[] ExtendKey(this byte[] key, params byte[]?[] additionalKeys)
        {
            int addLen = 0,
                offset = 0,
                len = additionalKeys.Length;
            for (int i = 0; i != len; addLen += additionalKeys[i]?.Length ?? 0, i++) ;
            byte[] res = new byte[addLen + key.Length];
            byte[]? addKey;
            Span<byte> resSpan = res.AsSpan();
            for (int i = len - 1; i >= 0; i--)
            {
                addKey = additionalKeys[i];
                if (addKey is null) continue;
                addKey.CopyTo(resSpan[offset..]);
                offset += addKey.Length;
                addKey.Clear();
            }
            key.CopyTo(resSpan[offset..]);
            key.Clear();
            return res;
        }
    }
}
