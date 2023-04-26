﻿using System.Security.Cryptography;
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
        /// Get the hash algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Algorithm</returns>
        public virtual HashAlgorithm GetHashAlgorithm(CryptoOptions? options = null)
        {
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !HashHelper.GetAlgorithm(Name).IsPostQuantum)
                    throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
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
                if (CryptoHelper.StrictPostQuantumSafety && !HashHelper.GetAlgorithm(Name).IsPostQuantum)
                    throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                options ??= DefaultOptions;
                options = HashHelper.GetDefaultOptions(options);
                HashAlgorithm algo = GetHashAlgorithm(options);
                try
                {
                    return new(new(target ?? Stream.Null, algo, writable ? CryptoStreamMode.Write : CryptoStreamMode.Read, options?.LeaveOpen ?? true), algo);
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
        public virtual byte[] Hash(Stream data, CryptoOptions? options = null)
        {
            options ??= DefaultOptions;
            options = HashHelper.GetDefaultOptions(options);
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !HashHelper.GetAlgorithm(Name).IsPostQuantum)
                    throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                options ??= DefaultOptions;
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
            options ??= DefaultOptions;
            options = HashHelper.GetDefaultOptions(options);
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !HashHelper.GetAlgorithm(Name).IsPostQuantum)
                    throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                options ??= DefaultOptions;
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
                throw CryptographicException.From(ex);
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
