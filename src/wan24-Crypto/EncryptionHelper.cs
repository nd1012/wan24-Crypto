﻿using System.Collections.Concurrent;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Encryption helper
    /// </summary>
    public static class EncryptionHelper
    {
        /// <summary>
        /// Default algorithm
        /// </summary>
        private static EncryptionAlgorithmBase _DefaultAlgorithm;
        /// <summary>
        /// Use the hybrid options?
        /// </summary>
        private static bool _UseHybridOptions = false;
        /// <summary>
        /// Enable the JSON wrapper for payload objects which don't implement <see cref="wan24.StreamSerializerExtensions.IStreamSerializer"/>?
        /// </summary>
        private static bool _EnableJsonWrapper = false;
        /// <summary>
        /// Registered algorithms
        /// </summary>
        public static readonly ConcurrentDictionary<string, EncryptionAlgorithmBase> Algorithms;

        /// <summary>
        /// Constructor
        /// </summary>
        static EncryptionHelper()
        {
            Algorithms = new(new KeyValuePair<string, EncryptionAlgorithmBase>[]
            {
                new(EncryptionAes256CbcAlgorithm.ALGORITHM_NAME, EncryptionAes256CbcAlgorithm.Instance)
            });
            _DefaultAlgorithm = Algorithms[EncryptionAes256CbcAlgorithm.ALGORITHM_NAME];
        }

        /// <summary>
        /// An object for thread synchronization
        /// </summary>
        public static object SyncObject { get; } = new();

        /// <summary>
        /// Default encryption algorithm
        /// </summary>
        public static EncryptionAlgorithmBase DefaultAlgorithm
        {
            get => _DefaultAlgorithm;
            set
            {
                lock (SyncObject) _DefaultAlgorithm = value;
            }
        }

        /// <summary>
        /// Use the hybrid options?
        /// </summary>
        public static bool UseHybridOptions
        {
            get => _UseHybridOptions;
            set
            {
                lock (SyncObject) _UseHybridOptions = value;
            }
        }

        /// <summary>
        /// Enable the JSON wrapper for payload objects which don't implement <see cref="wan24.StreamSerializerExtensions.IStreamSerializer"/>?
        /// </summary>
        public static bool EnableJsonWrapper
        {
            get => _EnableJsonWrapper;
            set
            {
                lock (SyncObject) _EnableJsonWrapper = value;
            }
        }

        /// <summary>
        /// Get an encryption stream
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="macStream">MAC stream</param>
        /// <param name="options">Options</param>
        /// <returns>Encryption stream, transform and MAC</returns>
        public static EncryptionStreams GetEncryptionStream(Stream rawData, Stream cipherData, MacStreams? macStream, CryptoOptions options)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.Algorithm!).GetEncryptionStream(rawData, cipherData, macStream, options);
        }

        /// <summary>
        /// Get an encryption stream
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="macStream">MAC stream</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Encryption stream, transform and MAC</returns>
        public static async Task<EncryptionStreams> GetEncryptionStreamAsync(
            Stream rawData,
            Stream cipherData,
            MacStreams? macStream,
            CryptoOptions options,
            CancellationToken cancellationToken = default
            )
        {
            options = GetDefaultOptions(options);
            return await GetAlgorithm(options.Algorithm!).GetEncryptionStreamAsync(rawData, cipherData, macStream, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Get a decryption stream
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="options">Options</param>
        /// <returns>Decryption stream and transform</returns>
        public static DecryptionStreams GetDecryptionStream(Stream cipherData, Stream rawData, CryptoOptions options)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.Algorithm!).GetDecryptionStream(cipherData, rawData, options);
        }

        /// <summary>
        /// Get a decryption stream
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Decryption stream and transform</returns>
        public static async Task<DecryptionStreams> GetDecryptionStreamAsync(
            Stream cipherData,
            Stream rawData,
            CryptoOptions options,
            CancellationToken cancellationToken = default
            )
        {
            options = GetDefaultOptions(options);
            return await GetAlgorithm(options.Algorithm!).GetDecryptionStreamAsync(cipherData, rawData, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="macStream">MAC stream</param>
        /// <returns>Cipher data</returns>
        public static Stream Encrypt(this Stream rawData, Stream cipherData, byte[] pwd, CryptoOptions? options = null, MacStreams? macStream = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.Algorithm!).Encrypt(rawData, cipherData, pwd, options, macStream);
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public static Stream Encrypt(this Stream rawData, Stream cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            options.SetKeys(key);
            return GetAlgorithm(options.Algorithm!).Encrypt(rawData, cipherData, key, options);
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="macStream">MAC stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Cipher data</returns>
        public static async Task EncryptAsync(
            this Stream rawData,
            Stream cipherData,
            byte[] pwd,
            CryptoOptions? options = null,
            MacStreams? macStream = null,
            CancellationToken cancellationToken = default
            )
        {
            options = GetDefaultOptions(options);
            await GetAlgorithm(options.Algorithm!).EncryptAsync(rawData, cipherData, pwd, options, macStream, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Cipher data</returns>
        public static async Task EncryptAsync(this Stream rawData, Stream cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            options = GetDefaultOptions(options);
            options.SetKeys(key);
            await GetAlgorithm(options.Algorithm!).EncryptAsync(rawData, cipherData, key, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static Stream Decrypt(this Stream cipherData, Stream rawData, byte[] pwd, CryptoOptions? options = null)
        {
            options = ReadOptions(cipherData, rawData, pwd, options);
            return GetAlgorithm(options.Algorithm!).Decrypt(cipherData, rawData, pwd, options);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public static Stream Decrypt(this Stream cipherData, Stream rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            options.SetKeys(key);
            options = ReadOptions(cipherData, rawData, key, options);
            return GetAlgorithm(options.Algorithm!).Decrypt(cipherData, rawData, options.Password!, options);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Raw data</returns>
        public static async Task DecryptAsync(this Stream cipherData, Stream rawData, byte[] pwd, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            options = await ReadOptionsAsync(cipherData, rawData, pwd, options, cancellationToken).DynamicContext();
            await GetAlgorithm(options.Algorithm!).DecryptAsync(cipherData, rawData, pwd, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Raw data</returns>
        public static async Task DecryptAsync(this Stream cipherData, Stream rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            options = GetDefaultOptions(options);
            options.SetKeys(key);
            options = await ReadOptionsAsync(cipherData, rawData, key, options, cancellationToken).DynamicContext();
            await GetAlgorithm(options.Algorithm!).DecryptAsync(cipherData, rawData, options.Password!, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Write the options
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Written options and used MAC stream</returns>
        public static (CryptoOptions Options, MacStreams? MacStream) WriteOptions(Stream rawData, Stream cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            options.SetKeys(key);
            return GetAlgorithm(options.Algorithm!).WriteOptions(rawData, cipherData, pwd: null, options);
        }

        /// <summary>
        /// Write the options
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Written options and used MAC stream</returns>
        public static (CryptoOptions Options, MacStreams? MacStream) WriteOptions(Stream rawData, Stream cipherData, byte[] pwd, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.Algorithm!).WriteOptions(rawData, cipherData, pwd, options);
        }

        /// <summary>
        /// Write the options
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Written options and used MAC stream</returns>
        public static async Task<(CryptoOptions Options, MacStreams? MacStream)> WriteOptionsAsync(
            Stream rawData,
            Stream cipherData,
            IAsymmetricPrivateKey key,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
        {
            options = GetDefaultOptions(options);
            options.SetKeys(key);
            return await GetAlgorithm(options.Algorithm!).WriteOptionsAsync(rawData, cipherData, pwd: null, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Write the options
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Written options and used MAC stream</returns>
        public static async Task<(CryptoOptions Options, MacStreams? MacStream)> WriteOptionsAsync(
            Stream rawData,
            Stream cipherData,
            byte[] pwd,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
        {
            options = GetDefaultOptions(options);
            return await GetAlgorithm(options.Algorithm!).WriteOptionsAsync(rawData, cipherData, pwd, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Read the options
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Red options</returns>
        public static CryptoOptions ReadOptions(Stream cipherData, Stream rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            options.SetKeys(key);
            return GetAlgorithm(options.Algorithm!).ReadOptions(cipherData, rawData, pwd: null, options);
        }

        /// <summary>
        /// Read the options
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Red options</returns>
        public static CryptoOptions ReadOptions(Stream cipherData, Stream rawData, byte[]? pwd = null, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.Algorithm!).ReadOptions(cipherData, rawData, pwd, options);
        }

        /// <summary>
        /// Read the options
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Red options</returns>
        public static async Task<CryptoOptions> ReadOptionsAsync(
            Stream cipherData,
            Stream rawData,
            IAsymmetricPrivateKey key,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
        {
            options = GetDefaultOptions(options);
            options.SetKeys(key);
            return await GetAlgorithm(options.Algorithm!).ReadOptionsAsync(cipherData, rawData, pwd: null, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Read the options
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Red options</returns>
        public static async Task<CryptoOptions> ReadOptionsAsync(
            Stream cipherData,
            Stream rawData,
            byte[]? pwd = null,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
        {
            options = GetDefaultOptions(options);
            return await GetAlgorithm(options.Algorithm!).ReadOptionsAsync(cipherData, rawData, pwd, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Get the default options used by the hash helper
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
                    options.Algorithm ??= DefaultAlgorithm.Name;
                    if (options.RequireMac) options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name;
                    if (options.RequireKdf && options.KdfAlgorithm == null)
                    {
                        options.KdfAlgorithm = KdfHelper.DefaultAlgorithm.Name;
                        options.KdfIterations = KdfHelper.DefaultAlgorithm.DefaultIterations;
                    }
                }
                if (UseHybridOptions) options = HybridAlgorithmHelper.GetEncryptionOptions(options);
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
        /// Validate streams
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="forEncryption">For encryption?</param>
        /// <param name="options">Options</param>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <returns>Valid?</returns>
        public static bool ValidateStreams(Stream rawData, Stream cipherData, bool forEncryption, CryptoOptions? options = null, bool throwOnError = true)
        {
            try
            {
                options ??= GetDefaultOptions(options);
                if (forEncryption)
                {
                    if (!rawData.CanRead || (options.MacIncluded && !cipherData.CanSeek) || !cipherData.CanWrite)
                    {
                        if (throwOnError)
                            throw new ArgumentException($"Readable raw data and writ{(options.MacIncluded ? "- and seek" : string.Empty)}able cipher data stream required", nameof(cipherData));
                        return false;
                    }
                }
                else
                {
                    options.Requirements = options.Flags;
                    if (!rawData.CanWrite || (options.RequireMac && !cipherData.CanSeek) || !cipherData.CanRead)
                    {
                        if (throwOnError)
                            throw new ArgumentException($"Writable raw data and read{(options.RequireMac ? "- and seek" : string.Empty)}able raw data stream required", nameof(cipherData));
                        return false;
                    }
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
            return true;
        }

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <returns>Algorithm</returns>
        public static EncryptionAlgorithmBase GetAlgorithm(string name)
            => Algorithms.TryGetValue(name, out EncryptionAlgorithmBase? algo)
                ? algo
                : throw new ArgumentException("Invalid algorithm", nameof(name));

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="value">Algorithm value</param>
        /// <returns>Algorithm</returns>
        public static EncryptionAlgorithmBase GetAlgorithm(int value)
            => Algorithms.Values.FirstOrDefault(a => a.Value == value) ?? throw new ArgumentException("Invalid algorithm", nameof(value));
    }
}
