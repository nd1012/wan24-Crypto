using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Hash helper
    /// </summary>
    public static class HashHelper
    {
        /// <summary>
        /// Default hash algorithm
        /// </summary>
        private static HashAlgorithmBase _DefaultAlgorithm;

        /// <summary>
        /// Registered hash algorithms
        /// </summary>
        public static readonly ConcurrentDictionary<string, HashAlgorithmBase> Algorithms;

        /// <summary>
        /// Constructor
        /// </summary>
        static HashHelper()
        {
            Algorithms = new(
            [
                new(HashMd5Algorithm.ALGORITHM_NAME, HashMd5Algorithm.Instance),
                new(HashSha1Algorithm.ALGORITHM_NAME, HashSha1Algorithm.Instance),
                new(HashSha256Algorithm.ALGORITHM_NAME, HashSha256Algorithm.Instance),
                new(HashSha384Algorithm.ALGORITHM_NAME, HashSha384Algorithm.Instance),
                new(HashSha512Algorithm.ALGORITHM_NAME, HashSha512Algorithm.Instance),
                new(HashSha3_256Algorithm.ALGORITHM_NAME, HashSha3_256Algorithm.Instance),
                new(HashSha3_384Algorithm.ALGORITHM_NAME, HashSha3_384Algorithm.Instance),
                new(HashSha3_512Algorithm.ALGORITHM_NAME, HashSha3_512Algorithm.Instance),
                new(HashShake128Algorithm.ALGORITHM_NAME, HashShake128Algorithm.Instance),
                new(HashShake256Algorithm.ALGORITHM_NAME, HashShake256Algorithm.Instance)
            ]);
            _DefaultAlgorithm = HashSha3_512Algorithm.Instance;
        }

        /// <summary>
        /// An object for thread synchronization
        /// </summary>
        public static object SyncObject { get; } = new();

        /// <summary>
        /// Default hash algorithm
        /// </summary>
        public static HashAlgorithmBase DefaultAlgorithm
        {
            get => _DefaultAlgorithm;
            set
            {
                lock (SyncObject) _DefaultAlgorithm = value;
            }
        }

        /// <summary>
        /// Pre-quantum algorithms
        /// </summary>
        public static IEnumerable<HashAlgorithmBase> PreQuantum
            => from algo in Algorithms.Values
               where !algo.IsPostQuantum
               select algo;

        /// <summary>
        /// Post-quantum algorithms
        /// </summary>
        public static IEnumerable<HashAlgorithmBase> PostQuantum
            => from algo in Algorithms.Values
               where algo.IsPostQuantum
               select algo;

        /// <summary>
        /// Get a hash stream
        /// </summary>
        /// <param name="target">Target stream</param>
        /// <param name="writable">Writable?</param>
        /// <param name="options">Options</param>
        /// <returns>Hash streams</returns>
        public static HashStreams GetHashStream(Stream? target = null, bool writable = true, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.HashAlgorithm!).GetHashStream(target, writable, options);
        }

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(this byte[] data, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.HashAlgorithm!).Hash(data, options);
        }

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(this ReadOnlySpan<byte> data, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.HashAlgorithm!).Hash(data, options);
        }

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static Span<byte> Hash(this ReadOnlySpan<byte> data, Span<byte> outputBuffer, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.HashAlgorithm!).Hash(data, outputBuffer, options);
        }

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(this Stream data, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.HashAlgorithm!).Hash(data, options);
        }

        /// <summary>
        /// Create a hash
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Hash</returns>
        public static async Task<byte[]> HashAsync(this Stream data, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            options = GetDefaultOptions(options);
            return await GetAlgorithm(options.HashAlgorithm!).HashAsync(data, options, cancellationToken).DynamicContext();
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
                if (options is null)
                {
                    options = DefaultAlgorithm.DefaultOptions;
                }
                else
                {
                    options.HashAlgorithm ??= DefaultAlgorithm.Name;
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
        public static HashAlgorithmBase GetAlgorithm(string name)
            => Algorithms.TryGetValue(name, out HashAlgorithmBase? algo)
                ? algo
                : throw new ArgumentException("Invalid algorithm", nameof(name));

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="value">Algorithm value</param>
        /// <returns>Algorithm</returns>
        public static HashAlgorithmBase GetAlgorithm(int value)
            => Algorithms.Values.FirstOrDefault(a => a.Value == value) ?? throw new ArgumentException("Invalid algorithm", nameof(value));

        /// <summary>
        /// Get the matching hash algorithm for a digest length
        /// </summary>
        /// <param name="len">Digest length in byte</param>
        /// <param name="allowedAlgos">Allowed hash algorithm names</param>
        /// <returns>Hash algorithm name</returns>
        public static string GetAlgorithmName(int len, params string[] allowedAlgos)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(len, 1);
            if (allowedAlgos.Length == 0) allowedAlgos = [.. Algorithms.Keys];
            return (from algo in Algorithms.Values
                    where algo.HashLength == len &&
                        allowedAlgos.Contains(algo.Name)
                    select algo.Name)
                    .FirstOrDefault() ??
                    throw CryptographicException.From($"Digest length {len} byte doesn't match any of the allowed MAC algorithms", new InvalidDataException());
        }

        /// <summary>
        /// Get the matching hash algorithm for a digest length
        /// </summary>
        /// <param name="len">Digest length in byte</param>
        /// <param name="algo">Hash algorithm name</param>
        /// <param name="allowedAlgos">Allowed hash algorithm names</param>
        /// <returns>If succeed</returns>
        public static bool TryGetAlgorithmName(int len, [NotNullWhen(returnValue: true)] out string? algo, params string[] allowedAlgos)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(len, 1);
            if (allowedAlgos.Length == 0) allowedAlgos = [.. Algorithms.Keys];
            algo = (from a in Algorithms.Values
                    where a.HashLength == len &&
                        allowedAlgos.Contains(a.Name)
                    select a.Name)
                    .FirstOrDefault();
            return algo is not null;
        }
    }
}
