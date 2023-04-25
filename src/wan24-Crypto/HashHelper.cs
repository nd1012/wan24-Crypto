using System.Collections.Concurrent;
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
            Algorithms = new(new KeyValuePair<string, HashAlgorithmBase>[]
            {
                new(HashMd5Algorithm.ALGORITHM_NAME, new HashMd5Algorithm()),
                new(HashSha1Algorithm.ALGORITHM_NAME, new HashSha1Algorithm()),
                new(HashSha256Algorithm.ALGORITHM_NAME, new HashSha256Algorithm()),
                new(HashSha384Algorithm.ALGORITHM_NAME, new HashSha384Algorithm()),
                new(HashSha512Algorithm.ALGORITHM_NAME, new HashSha512Algorithm())
            });
            _DefaultAlgorithm = Algorithms[HashSha512Algorithm.ALGORITHM_NAME];
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
            if (options == null)
            {
                options = DefaultAlgorithm.DefaultOptions;
            }
            else
            {
                options.HashAlgorithm ??= DefaultAlgorithm.Name;
            }
            return options;
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
    }
}
