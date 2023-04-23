using System.Collections.Concurrent;

namespace wan24.Crypto
{
    /// <summary>
    /// KDF helper
    /// </summary>
    public static class KdfHelper
    {
        /// <summary>
        /// Default KDF algorithm
        /// </summary>
        private static KdfAlgorithmBase _DefaultAlgorithm;

        /// <summary>
        /// Registered KDF algorithms
        /// </summary>
        public static readonly ConcurrentDictionary<string, KdfAlgorithmBase> Algorithms;

        /// <summary>
        /// Constructor
        /// </summary>
        static KdfHelper()
        {
            Algorithms = new(new KeyValuePair<string, KdfAlgorithmBase>[]
            {
                new(KdfPbKdf2Algorithm.ALGORITHM_NAME, new KdfPbKdf2Algorithm())
            });
            _DefaultAlgorithm = Algorithms[KdfPbKdf2Algorithm.ALGORITHM_NAME];
        }

        /// <summary>
        /// An object for thread synchronization
        /// </summary>
        public static object SyncObject { get; } = new();

        /// <summary>
        /// Default KDF algorithm
        /// </summary>
        public static KdfAlgorithmBase DefaultAlgorithm
        {
            get => _DefaultAlgorithm;
            set
            {
                lock (SyncObject) _DefaultAlgorithm = value;
            }
        }

        /// <summary>
        /// Stretch a password
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="len">Required password length</param>
        /// <param name="salt">Salt</param>
        /// <param name="options">Options</param>
        /// <returns>Stretched password and the used salt</returns>
        public static (byte[] Stretched, byte[] Salt) Stretch(this byte[] pwd, int len, byte[]? salt = null, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.KdfAlgorithm!).Stretch(pwd, len, salt, options);
        }

        /// <summary>
        /// Get the default options used by the KDF helper
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions GetDefaultOptions(CryptoOptions? options = null)
        {
            if (options == null)
            {
                options = DefaultAlgorithm.DefaultOptions;
            }
            else if (options.KdfAlgorithm == null)
            {
                options.KdfAlgorithm = DefaultAlgorithm.Name;
                options.KdfIterations = DefaultAlgorithm.DefaultIterations;
            }
            return options;
        }

        /// <summary>
        /// Get the KDF algorithm name
        /// </summary>
        /// <param name="algo">KDF algorithm value</param>
        /// <returns>KDF algorithm name</returns>
        public static string GetAlgorithmName(int algo)
            => Algorithms.Values.Where(a => a.Value == algo).Select(a => a.Name).FirstOrDefault()
                ?? throw new ArgumentException("Invalid algorithm", nameof(algo));

        /// <summary>
        /// Get the KDF algorithm value
        /// </summary>
        /// <param name="algo">KDF algorithm name</param>
        /// <returns>KDF algorithm value</returns>
        public static int GetAlgorithmValue(string algo)
            => Algorithms.TryGetValue(algo, out KdfAlgorithmBase? a)
                ? a.Value
                : throw new ArgumentException("Invalid algorithm", nameof(algo));

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <returns>Algorithm</returns>
        public static KdfAlgorithmBase GetAlgorithm(string name)
            => Algorithms.TryGetValue(name, out KdfAlgorithmBase? algo)
                ? algo
                : throw new ArgumentException("Invalid algorithm", nameof(name));

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="value">Algorithm value</param>
        /// <returns>Algorithm</returns>
        public static KdfAlgorithmBase GetAlgorithm(int value)
            => Algorithms.TryGetValue(GetAlgorithmName(value), out KdfAlgorithmBase? algo)
                ? algo
                : throw new ArgumentException("Invalid algorithm", nameof(value));
    }
}
