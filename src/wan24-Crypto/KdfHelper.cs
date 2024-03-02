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
            Algorithms = new(
            [
                new(KdfPbKdf2Algorithm.ALGORITHM_NAME, KdfPbKdf2Algorithm.Instance),
                new(KdfSp800_108HmacCtrKbKdfAlgorithm.ALGORITHM_NAME, KdfSp800_108HmacCtrKbKdfAlgorithm.Instance)
            ]);
            _DefaultAlgorithm = KdfPbKdf2Algorithm.Instance;
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
        /// Pre-quantum algorithms
        /// </summary>
        public static IEnumerable<KdfAlgorithmBase> PreQuantum
            => from algo in Algorithms.Values
               where !algo.IsPostQuantum
               select algo;

        /// <summary>
        /// Post-quantum algorithms
        /// </summary>
        public static IEnumerable<KdfAlgorithmBase> PostQuantum
            => from algo in Algorithms.Values
               where algo.IsPostQuantum
               select algo;

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
            try
            {
                if (options is null)
                {
                    options = DefaultAlgorithm.DefaultOptions;
                }
                else if (options.KdfAlgorithm is null)
                {
                    options.KdfAlgorithm = DefaultAlgorithm.Name;
                    options.KdfIterations = DefaultAlgorithm.DefaultIterations;
                    options.KdfOptions = DefaultAlgorithm.DefaultOptions.KdfOptions;
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
            => Algorithms.Values.FirstOrDefault(a => a.Value == value) ?? throw new ArgumentException("Invalid algorithm", nameof(value));
    }
}
