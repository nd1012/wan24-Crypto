using System.Collections.Concurrent;

namespace wan24.Crypto
{
    /// <summary>
    /// Asymmetric helper
    /// </summary>
    public static class AsymmetricHelper
    {
        /// <summary>
        /// Default key exchange algorithm
        /// </summary>
        private static IAsymmetricAlgorithm _DefaultKeyExchangeAlgorithm;
        /// <summary>
        /// Default signature algorithm
        /// </summary>
        private static IAsymmetricAlgorithm _DefaultSignatureAlgorithm;

        /// <summary>
        /// Registered algorithms
        /// </summary>
        public static readonly ConcurrentDictionary<string, IAsymmetricAlgorithm> Algorithms;

        /// <summary>
        /// Constructor
        /// </summary>
        static AsymmetricHelper()
        {
            Algorithms = new(new KeyValuePair<string, IAsymmetricAlgorithm>[]
            {
                new(AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME, new AsymmetricEcDiffieHellmanAlgorithm()),
                new(AsymmetricEcDsaAlgorithm.ALGORITHM_NAME, new AsymmetricEcDsaAlgorithm())
            });
            _DefaultKeyExchangeAlgorithm = Algorithms[AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME];
            _DefaultSignatureAlgorithm = Algorithms[AsymmetricEcDsaAlgorithm.ALGORITHM_NAME];
        }

        /// <summary>
        /// Default key exchange algorithm
        /// </summary>
        public static IAsymmetricAlgorithm DefaultKeyExchangeAlgorithm
        {
            get => _DefaultKeyExchangeAlgorithm;
            set
            {
                if (!value.CanExchangeKey) throw new ArgumentException("Algorithm can't key exchange", nameof(value));
                _DefaultKeyExchangeAlgorithm = value;
            }
        }

        /// <summary>
        /// Default signature algorithm
        /// </summary>
        public static IAsymmetricAlgorithm DefaultSignatureAlgorithm
        {
            get => _DefaultSignatureAlgorithm;
            set
            {
                if (!value.CanSign) throw new ArgumentException("Algorithm can't sign", nameof(value));
                _DefaultSignatureAlgorithm = value;
            }
        }

        /// <summary>
        /// Create a new key pair
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Private key</returns>
        public static IAsymmetricPrivateKey CreateKeyPair(CryptoOptions options)
        {
            if (options.AsymmetricAlgorithm == null) throw new ArgumentException("Missing asymmetric algorithm name", nameof(options));
            return GetAlgorithm(options.AsymmetricAlgorithm).CreateKeyPair(options);
        }

        /// <summary>
        /// Create a new key pair for key exchange
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Private key</returns>
        public static IAsymmetricPrivateKey CreateKeyExchangeKeyPair(CryptoOptions? options = null)
        {
            options = GetDefaultKeyExchangeOptions(options);
            return GetAlgorithm(options.AsymmetricAlgorithm!).CreateKeyPair(options);
        }

        /// <summary>
        /// Create a new key pair for signature
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Private key</returns>
        public static IAsymmetricPrivateKey CreateSignatureKeyPair(CryptoOptions? options = null)
        {
            options = GetDefaultSignatureOptions(options);
            return GetAlgorithm(options.AsymmetricAlgorithm!).CreateKeyPair(options);
        }

        /// <summary>
        /// Get the default key exchange options used by the asymmetric helper
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions GetDefaultKeyExchangeOptions(CryptoOptions? options = null)
        {
            if (options == null)
            {
                options = DefaultKeyExchangeAlgorithm.DefaultOptions;
            }
            else
            {
                if (options.AsymmetricAlgorithm == null)
                {
                    options.AsymmetricAlgorithm = DefaultKeyExchangeAlgorithm.Name;
                    options.AsymmetricKeyBits = DefaultKeyExchangeAlgorithm.DefaultKeySize;
                }
            }
            return options;
        }

        /// <summary>
        /// Get the default signature options used by the asymmetric helper
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions GetDefaultSignatureOptions(CryptoOptions? options = null)
        {
            if (options == null)
            {
                options = DefaultSignatureAlgorithm.DefaultOptions;
            }
            else
            {
                if (options.AsymmetricAlgorithm == null)
                {
                    options.AsymmetricAlgorithm = DefaultSignatureAlgorithm.Name;
                    options.AsymmetricKeyBits = DefaultSignatureAlgorithm.DefaultKeySize;
                }
            }
            return options;
        }

        /// <summary>
        /// Get the hash algorithm name
        /// </summary>
        /// <param name="algo">Hash algorithm value</param>
        /// <returns>Hash algorithm name</returns>
        public static string GetAlgorithmName(int algo)
            => Algorithms.Values.Where(a => a.Value == algo).Select(a => a.Name).FirstOrDefault()
                ?? throw new ArgumentException("Invalid algorithm", nameof(algo));

        /// <summary>
        /// Get the hash algorithm value
        /// </summary>
        /// <param name="algo">Hash algorithm name</param>
        /// <returns>Hash algorithm value</returns>
        public static int GetAlgorithmValue(string algo)
            => Algorithms.TryGetValue(algo, out IAsymmetricAlgorithm? a)
                ? a.Value
                : throw new ArgumentException("Invalid algorithm", nameof(algo));

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <returns>Algorithm</returns>
        public static IAsymmetricAlgorithm GetAlgorithm(string name)
            => Algorithms.TryGetValue(name, out IAsymmetricAlgorithm? algo)
                ? algo
                : throw new ArgumentException("Invalid algorithm", nameof(name));

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="value">Algorithm value</param>
        /// <returns>Algorithm</returns>
        public static IAsymmetricAlgorithm GetAlgorithm(int value)
            => Algorithms.TryGetValue(GetAlgorithmName(value), out IAsymmetricAlgorithm? algo)
                ? algo
                : throw new ArgumentException("Invalid algorithm", nameof(value));
    }
}
