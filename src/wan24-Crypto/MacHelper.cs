﻿using System.Collections.Concurrent;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// MAC helper
    /// </summary>
    public static class MacHelper
    {
        /// <summary>
        /// Default MAC algorithm
        /// </summary>
        private static MacAlgorithmBase _DefaultAlgorithm;

        /// <summary>
        /// Registered MAC algorithms
        /// </summary>
        public static readonly ConcurrentDictionary<string, MacAlgorithmBase> Algorithms;

        /// <summary>
        /// Constructor
        /// </summary>
        static MacHelper()
        {
            Algorithms = new(new KeyValuePair<string, MacAlgorithmBase>[]
            {
                new(MacHmacSha1Algorithm.ALGORITHM_NAME, MacHmacSha1Algorithm.Instance),
                new(MacHmacSha256Algorithm.ALGORITHM_NAME, MacHmacSha256Algorithm.Instance),
                new(MacHmacSha384Algorithm.ALGORITHM_NAME, MacHmacSha384Algorithm.Instance),
                new(MacHmacSha512Algorithm.ALGORITHM_NAME, MacHmacSha512Algorithm.Instance)
            });
            _DefaultAlgorithm = Algorithms[MacHmacSha512Algorithm.ALGORITHM_NAME];
        }

        /// <summary>
        /// An object for thread synchronization
        /// </summary>
        public static object SyncObject { get; } = new();

        /// <summary>
        /// Default MAC algorithm
        /// </summary>
        public static MacAlgorithmBase DefaultAlgorithm
        {
            get => _DefaultAlgorithm;
            set
            {
                lock (SyncObject) _DefaultAlgorithm = value;
            }
        }

        /// <summary>
        /// Get a MAC stream
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="target">Target stream</param>
        /// <param name="writable">Writable?</param>
        /// <param name="options">Options</param>
        /// <returns>MAC streams</returns>
        public static MacStreams GetMacStream(byte[] pwd, Stream? target = null, bool writable = true, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).GetMacStream(pwd, target, writable, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this byte[] data, byte[] pwd, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).Mac(data, pwd, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this ReadOnlySpan<byte> data, byte[] pwd, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).Mac(data, pwd, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static Span<byte> Mac(this ReadOnlySpan<byte> data, byte[] pwd, Span<byte> outputBuffer, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).Mac(data, pwd, outputBuffer, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this Stream data, byte[] pwd, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).Mac(data, pwd, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>MAC</returns>
        public static async Task<byte[]> MacAsync(this Stream data, byte[] pwd, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            options = GetDefaultOptions(options);
            return await GetAlgorithm(options.MacAlgorithm!).MacAsync(data, pwd, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Get the default options used by the MAC helper
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions GetDefaultOptions(CryptoOptions? options = null)
        {
            try
            {
                if (options == null)
                {
                    options = DefaultAlgorithm.DefaultOptions;
                }
                else
                {
                    options.MacAlgorithm ??= DefaultAlgorithm.Name;
                }
                return options;
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
        /// Get an algorithm
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <returns>Algorithm</returns>
        public static MacAlgorithmBase GetAlgorithm(string name)
            => Algorithms.TryGetValue(name, out MacAlgorithmBase? algo)
                ? algo
                : throw new ArgumentException("Invalid algorithm", nameof(name));

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="value">Algorithm value</param>
        /// <returns>Algorithm</returns>
        public static MacAlgorithmBase GetAlgorithm(int value)
            => Algorithms.Values.FirstOrDefault(a => a.Value == value) ?? throw new ArgumentException("Invalid algorithm", nameof(value));
    }
}
