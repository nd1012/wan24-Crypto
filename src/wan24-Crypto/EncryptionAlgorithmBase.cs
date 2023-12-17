using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a symmetric encryption algorithm
    /// </summary>
    public abstract partial record class EncryptionAlgorithmBase : CryptoAlgorithmBase
    {
        /// <summary>
        /// Default options
        /// </summary>
        protected CryptoOptions _DefaultOptions;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        protected EncryptionAlgorithmBase(string name, int value) : base(name, value) {
            _DefaultOptions = new()
            {
                Algorithm = name
            };
            if (RequireMacAuthentication) _DefaultOptions.RequireMac = true;
        }

        /// <summary>
        /// Default options
        /// </summary>
        public CryptoOptions DefaultOptions => EncryptionHelper.GetDefaultOptions(_DefaultOptions.GetCopy());

        /// <summary>
        /// Ensure that the given options include the default options for this algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public virtual CryptoOptions EnsureDefaultOptions(CryptoOptions? options = null)
        {
            if (options is null) return DefaultOptions;
            options.Algorithm = _DefaultOptions.Algorithm;
            if (RequireMacAuthentication && options.MacAlgorithm is null) MacHelper.GetDefaultOptions(options);
            return options;
        }

        /// <summary>
        /// Ensure a key with a valid length
        /// </summary>
        /// <param name="key">Key (won't be cleared)</param>
        /// <returns>Key with a valid length (if the given <c>key</c> had a valid length already, this is a copy; should be cleared)</returns>
        public abstract byte[] EnsureValidKeyLength(byte[] key);

        /// <summary>
        /// Determine if a key length is valid
        /// </summary>
        /// <param name="len">Key length in bytes</param>
        /// <returns>If the key length is valid</returns>
        public abstract bool IsKeyLengthValid(int len);

        /// <summary>
        /// Create random IV bytes
        /// </summary>
        /// <returns>IV bytes</returns>
        protected virtual byte[] CreateIvBytes() => RND.GetBytes(IvSize);

        /// <summary>
        /// Get a key with a valid length
        /// </summary>
        /// <param name="key">Key (won't be cleared)</param>
        /// <param name="len">Required key length in bytes</param>
        /// <returns>Key with a valid length (if the given <c>key</c> had a valid length already, this is a copy; should be cleared)</returns>
        protected virtual byte[] GetValidLengthKey(byte[] key, int len)
            => key.Length == len ? key.CloneArray() : len switch
            {
                HashMd5Algorithm.HASH_LENGTH => HashMd5Algorithm.Instance.Hash(key),
                HashSha1Algorithm.HASH_LENGTH => HashSha1Algorithm.Instance.Hash(key),
                HashSha256Algorithm.HASH_LENGTH => HashSha256Algorithm.Instance.Hash(key),
                HashSha384Algorithm.HASH_LENGTH => HashSha384Algorithm.Instance.Hash(key),
                HashSha512Algorithm.HASH_LENGTH => HashSha512Algorithm.Instance.Hash(key),
                _ => throw CryptographicException.From($"Can't process for desired key length {len} bytes", new NotSupportedException())
            };

        /// <summary>
        /// Read the fixed IV bytes
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <returns>IV bytes</returns>
        protected virtual byte[] ReadFixedIvBytes(Stream cipherData, CryptoOptions options)
        {
            try
            {
                byte[] res = new byte[IvSize];
                cipherData.ReadExactly(res);
                if (((options.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Iv) == RngSeedingTypes.Iv)
                    RND.AddSeed(res);
                return res;
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
        /// Read the fixed IV bytes
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>IV bytes</returns>
        protected virtual async Task<byte[]> ReadFixedIvBytesAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            try
            {
                byte[] res = new byte[IvSize];
                await cipherData.ReadExactlyAsync(res, cancellationToken).DynamicContext();
                if (((options.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Iv) == RngSeedingTypes.Iv)
                    await RND.AddSeedAsync(res, cancellationToken).DynamicContext();
                return res;
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
        /// Read the variable IV bytes
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <returns>IV bytes</returns>
        protected virtual byte[] ReadVariableIvBytes(Stream cipherData, CryptoOptions options)
        {
            try
            {
                byte[] res = cipherData.ReadBytes(options.CustomSerializerVersion, minLen: IvSize, maxLen: byte.MaxValue).Value;
                if (((options.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Iv) == RngSeedingTypes.Iv)
                    RND.AddSeed(res);
                return res;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From($"Failed to read IV bytes: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Read the variable IV bytes
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>IV bytes</returns>
        protected virtual async Task<byte[]> ReadVariableIvBytesAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            try
            {
                byte[] res = (await cipherData.ReadBytesAsync(options.CustomSerializerVersion, minLen: IvSize, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                if (((options.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Iv) == RngSeedingTypes.Iv)
                    await RND.AddSeedAsync(res, cancellationToken).DynamicContext();
                return res;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From($"Failed to read IV bytes: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Encode flags
        /// </summary>
        /// <param name="flags">Flags</param>
        /// <param name="buffer">Buffer</param>
        protected virtual void EncodeFlags(CryptoFlags flags, Span<byte> buffer)
        {
            if (buffer.Length < 3) throw new ArgumentException("Buffer soo small", nameof(buffer));
            int f = (int)flags;
            buffer[0] = (byte)f;
            buffer[1] = (byte)(f >> 8);
            buffer[2] = (byte)(f >> 16);
        }

        /// <summary>
        /// Decode flags
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <returns>Flags</returns>
        protected virtual CryptoFlags DecodeFlags(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < 3) throw new ArgumentException("Buffer soo small", nameof(buffer));
            int res = buffer[0];
            res |= buffer[1] << 8;
            res |= buffer[2] << 16;
            return (CryptoFlags)res;
        }
    }
}
