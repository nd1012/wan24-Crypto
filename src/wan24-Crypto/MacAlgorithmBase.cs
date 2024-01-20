using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for an MAC algorithm
    /// </summary>
    public abstract record class MacAlgorithmBase : CryptoAlgorithmBase
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
        public CryptoOptions DefaultOptions => MacHelper.GetDefaultOptions(_DefaultOptions.GetCopy());

        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public abstract int MacLength { get; }

        /// <summary>
        /// Ensure that the given options include the default options for this algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public virtual CryptoOptions EnsureDefaultOptions(CryptoOptions? options = null)
        {
            if (options is null) return DefaultOptions;
            options.MacAlgorithm = _DefaultOptions.MacAlgorithm;
            return options;
        }

        /// <summary>
        /// Get the MAC algorithm
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Algorithm</returns>
        public virtual KeyedHashAlgorithm GetMacAlgorithm(byte[] pwd, CryptoOptions? options = null)
        {
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                return GetMacAlgorithmInt(pwd, options);
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
        /// Get a MAC stream
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="target">Target stream</param>
        /// <param name="writable">Writable?</param>
        /// <param name="options">Options</param>
        /// <returns>MAC stream and crypto transform</returns>
        public virtual MacStreams GetMacStream(byte[] pwd, Stream? target = null, bool writable = true, CryptoOptions? options = null)
        {
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                options = MacHelper.GetDefaultOptions(options?.GetCopy() ?? DefaultOptions);
                KeyedHashAlgorithm algo = GetMacAlgorithm(pwd, options);
                try
                {
                    return new(
                        new(
                            new WrapperStream(target ?? Stream.Null, leaveOpen: options?.LeaveOpen ?? false),
                            algo, 
                            writable ? CryptoStreamMode.Write : CryptoStreamMode.Read, 
                            leaveOpen: false
                            ), 
                        algo
                        );
                }
                catch
                {
                    algo.Dispose();
                    throw;
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
        /// Create an MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public virtual byte[] Mac(ReadOnlySpan<byte> data, byte[] pwd, CryptoOptions? options = null)
        {
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                options = MacHelper.GetDefaultOptions(options?.GetCopy() ?? DefaultOptions);
                byte[] res = new byte[MacLength];
                if (!GetMacAlgorithm(pwd, options).TryComputeHash(data, res, out _)) throw new IOException($"Failed to compute the final MAC");
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
        /// Create an MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public virtual Span<byte> Mac(ReadOnlySpan<byte> data, byte[] pwd, Span<byte> outputBuffer, CryptoOptions? options = null)
        {
            try
            {
                if (outputBuffer.Length < MacLength) throw new ArgumentOutOfRangeException(nameof(outputBuffer));
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                options = MacHelper.GetDefaultOptions(options?.GetCopy() ?? DefaultOptions);
                if (!GetMacAlgorithm(pwd, options).TryComputeHash(data, outputBuffer, out _)) throw new IOException($"Failed to compute the final MAC");
                return outputBuffer;
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
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                options = MacHelper.GetDefaultOptions(options?.GetCopy() ?? DefaultOptions);
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
                throw CryptographicException.From(ex);
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
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                options = MacHelper.GetDefaultOptions(options?.GetCopy() ?? DefaultOptions);
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
                throw await CryptographicException.FromAsync(ex);
            }
        }

        /// <summary>
        /// Get the MAC algorithm
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Algorithm</returns>
        protected abstract KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options);
    }
}
