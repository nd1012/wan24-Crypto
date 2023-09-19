using System.Text;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// KDF extensions
    /// </summary>
    public static class KdfExtensions
    {
        /// <summary>
        /// Stretch a password
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="len">Required password length</param>
        /// <param name="salt">Salt</param>
        /// <param name="options">Options</param>
        /// <returns>Stretched password and the used salt</returns>
        public static (byte[] Stretched, byte[] Salt) Stretch(this ReadOnlySpan<char> pwd, int len, byte[]? salt = null, CryptoOptions? options = null)
        {
            using RentedArrayRefStruct<byte> buffer = new(Encoding.UTF8.GetByteCount(pwd), clean: false)
            {
                Clear = true
            };
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetEncoder().Convert(pwd, buffer.Span, flush: true, out int used, out int written, out bool completed);
            if (used != pwd.Length || !completed) throw new ArgumentException("Can't get UTF-8 bytes from password", nameof(pwd));
            if (written == buffer.Length)
            {
                return buffer.Array.Stretch(len, salt, options);
            }
            else
            {
                byte[] pwdBytes = buffer.Span[..written].ToArray();
                try
                {
                    return pwdBytes.Stretch(len, salt, options);
                }
                finally
                {
                    pwdBytes.Clear();
                }
            }
        }
        /// <summary>
        /// Stretch a password
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="len">Required password length</param>
        /// <param name="salt">Salt</param>
        /// <param name="options">Options</param>
        /// <returns>Stretched password and the used salt</returns>
        public static (byte[] Stretched, byte[] Salt) Stretch(this string pwd, int len, byte[]? salt = null, CryptoOptions? options = null)
        {
            using RentedArrayRefStruct<byte> buffer = new(Encoding.UTF8.GetByteCount(pwd), clean: false)
            {
                Clear = true
            };
            int written = pwd.GetBytes(buffer.Span);
            if (written == buffer.Length && buffer.Length == buffer.Array.Length)
            {
                return buffer.Array.Stretch(len, salt, options);
            }
            else
            {
                byte[] pwdBytes = buffer.Span[..written].ToArray();
                try
                {
                    return pwdBytes.Stretch(len, salt, options);
                }
                finally
                {
                    pwdBytes.Clear();
                }
            }
        }
    }
}
