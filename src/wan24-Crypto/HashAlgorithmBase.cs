using System.Security.Cryptography;
using wan24.Core;
using static wan24.Core.TranslationHelper;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a hash algorithm
    /// </summary>
    public abstract record class HashAlgorithmBase : CryptoAlgorithmBase
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
        public CryptoOptions DefaultOptions => HashHelper.GetDefaultOptions(_DefaultOptions.GetCopy());

        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public abstract int HashLength { get; }

        /// <inheritdoc/>
        public override IEnumerable<Status> State
        {
            get
            {
                foreach (Status status in base.State) yield return status;
                yield return new(__("Hash length"), HashLength, __("The hash (digest) length in bytes"));
            }
        }

        /// <summary>
        /// Ensure that the given options include the default options for this algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public virtual CryptoOptions EnsureDefaultOptions(CryptoOptions? options = null)
        {
            if (options is null) return DefaultOptions;
            options.HashAlgorithm = _DefaultOptions.Algorithm;
            return options;
        }

        /// <summary>
        /// Get the hash algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Algorithm</returns>
        public virtual HashAlgorithm GetHashAlgorithm(CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                return GetHashAlgorithmInt(options);
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
        /// Get a hash stream
        /// </summary>
        /// <param name="target">Target stream</param>
        /// <param name="writable">Writable?</param>
        /// <param name="options">Options</param>
        /// <returns>Hash streams</returns>
        public virtual HashStreams GetHashStream(Stream? target = null, bool writable = true, CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options = options?.GetCopy() ?? DefaultOptions;
                options = HashHelper.GetDefaultOptions(options);
                HashAlgorithm algo = GetHashAlgorithm(options);
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
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public byte[] Hash(byte[] data, CryptoOptions? options = null) => Hash((ReadOnlySpan<byte>)data.AsSpan(), options);

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public virtual byte[] Hash(ReadOnlySpan<byte> data, CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options = options?.GetCopy() ?? DefaultOptions;
                options = HashHelper.GetDefaultOptions(options);
                byte[] res = new byte[HashLength];
                using HashAlgorithm hash = GetHashAlgorithm(options);
                if (!hash.TryComputeHash(data, res, out int written)) throw new IOException($"Failed to compute the final hash");
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
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public virtual Span<byte> Hash(ReadOnlySpan<byte> data, Span<byte> outputBuffer, CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                if (outputBuffer.Length < HashLength) throw new ArgumentOutOfRangeException(nameof(outputBuffer));
                options = options?.GetCopy() ?? DefaultOptions;
                options = HashHelper.GetDefaultOptions(options);
                using HashAlgorithm hash = GetHashAlgorithm(options);
                if (!hash.TryComputeHash(data, outputBuffer, out int written)) throw new IOException($"Failed to compute the final hash");
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
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public virtual byte[] Hash(Stream data, CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options = options?.GetCopy() ?? DefaultOptions;
                options = HashHelper.GetDefaultOptions(options);
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
                throw CryptographicException.From(ex);
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
                EnsureAllowed();
                options = options?.GetCopy() ?? DefaultOptions;
                options = HashHelper.GetDefaultOptions(options);
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
                throw await CryptographicException.FromAsync(ex);
            }
        }

        /// <summary>
        /// Get the hash algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Algorithm</returns>
        protected abstract HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options);
    }
}
