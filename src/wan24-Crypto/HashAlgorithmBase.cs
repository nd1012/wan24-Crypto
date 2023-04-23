using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a hash algorithm
    /// </summary>
    public abstract class HashAlgorithmBase : CryptoAlgorithmBase
    {
        /// <summary>
        /// Default options
        /// </summary>
        protected readonly CryptoOptions _DefaultOptions;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        protected HashAlgorithmBase(string name, int value) : base(name, value) => _DefaultOptions = new()
        {
            HashAlgorithm = name
        };

        /// <summary>
        /// Default options
        /// </summary>
        public CryptoOptions DefaultOptions => _DefaultOptions.Clone();

        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public abstract int HashLength { get; }

        /// <summary>
        /// Get a hash stream
        /// </summary>
        /// <param name="target">Target stream</param>
        /// <param name="writable">Writable?</param>
        /// <param name="options">Options</param>
        /// <returns>Hash streams</returns>
        public abstract HashStreams GetHashStream(Stream? target = null, bool writable = true, CryptoOptions? options = null);

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public virtual byte[] Hash(Stream data, CryptoOptions? options = null)
        {
            try
            {
                using HashStreams hash = GetHashStream(options: options);
                data.CopyTo(hash.Stream);
                hash.Stream.FlushFinalBlock();
                return hash.Transform.Hash ?? throw new InvalidProgramException();
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
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Hash</returns>
        public virtual async Task<byte[]> HashAsync(Stream data, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            try
            {
                HashStreams hash = GetHashStream(options: options);
                await using (hash.DynamicContext())
                {
                    await data.CopyToAsync(hash.Stream, cancellationToken).DynamicContext();
                    await hash.Stream.FlushFinalBlockAsync(cancellationToken).DynamicContext();
                    return hash.Transform.Hash ?? throw new InvalidProgramException();
                }
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
        /// Get a hash stream
        /// </summary>
        /// <param name="algo">Hash algorithm</param>
        /// <param name="target">Target stream</param>
        /// <param name="writable">Writable?</param>
        /// <param name="options">Options</param>
        /// <returns>Hash streams</returns>
        protected virtual HashStreams GetHashStreamInt(HashAlgorithm algo, Stream? target, bool writable, CryptoOptions? options)
        {
            try
            {
                return new(new(target ?? Stream.Null, algo, writable ? CryptoStreamMode.Write : CryptoStreamMode.Read, options?.LeaveOpen ?? true), algo);
            }
            catch (CryptographicException)
            {
                algo.Dispose();
                throw;
            }
            catch (Exception ex)
            {
                algo.Dispose();
                throw new CryptographicException(ex.Message, ex);
            }
        }
    }
}
