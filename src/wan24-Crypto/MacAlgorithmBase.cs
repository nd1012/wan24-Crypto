using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for an MAC algorithm
    /// </summary>
    public abstract class MacAlgorithmBase : CryptoAlgorithmBase
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
        protected MacAlgorithmBase(string name, int value) : base(name, value)
            => _DefaultOptions = new()
            {
                MacAlgorithm = Name
            };

        /// <summary>
        /// Default options
        /// </summary>
        public CryptoOptions DefaultOptions => _DefaultOptions.Clone();

        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public abstract int MacLength { get; }

        /// <summary>
        /// Get a MAC stream
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="target">Target stream</param>
        /// <param name="writable">Writable?</param>
        /// <param name="options">Options</param>
        /// <returns>MAC stream and crypto transform</returns>
        public abstract MacStreams GetMacStream(byte[] pwd, Stream? target = null, bool writable = true, CryptoOptions? options = null);

        /// <summary>
        /// Create an MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public virtual byte[] Mac(Stream data, byte[] pwd, CryptoOptions? options = null)
        {
            try
            {
                using MacStreams mac = GetMacStream(pwd, options: options);
                data.CopyTo(mac.Stream);
                mac.Stream.FlushFinalBlock();
                return mac.Transform.Hash ?? throw new InvalidProgramException();
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
        /// Create an MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>MAC</returns>
        public virtual async Task<byte[]> MacAsync(Stream data, byte[] pwd, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            try
            {
                MacStreams mac = GetMacStream(pwd, options: options);
                await using (mac.DynamicContext())
                {
                    await data.CopyToAsync(mac.Stream, cancellationToken).DynamicContext();
                    await mac.Stream.FlushFinalBlockAsync(cancellationToken).DynamicContext();
                    return mac.Transform.Hash ?? throw new InvalidProgramException();
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
        /// Get a MAC stream
        /// </summary>
        /// <param name="algo">MAC algorithm</param>
        /// <param name="target">Target stream</param>
        /// <param name="writable">Writable?</param>
        /// <param name="options">Options</param>
        /// <returns>MAC stream and crypto transform</returns>
        protected virtual MacStreams GetMacStreamInt(KeyedHashAlgorithm algo, Stream? target, bool writable, CryptoOptions? options)
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
