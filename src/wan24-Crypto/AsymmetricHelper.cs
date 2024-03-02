using System.Collections.Concurrent;
using wan24.Core;

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
        /// Use the hybrid key exchange options?
        /// </summary>
        private static bool _UseHybridKeyExchangeOptions = false;
        /// <summary>
        /// Use the hybrid signature options?
        /// </summary>
        private static bool _UseHybridSignatureOptions = false;

        /// <summary>
        /// Registered algorithms
        /// </summary>
        public static readonly ConcurrentDictionary<string, IAsymmetricAlgorithm> Algorithms;

        /// <summary>
        /// Constructor
        /// </summary>
        static AsymmetricHelper()
        {
            Algorithms = new(
            [
                new(AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME, AsymmetricEcDiffieHellmanAlgorithm.Instance),
                new(AsymmetricEcDsaAlgorithm.ALGORITHM_NAME, AsymmetricEcDsaAlgorithm.Instance)
            ]);
            _DefaultKeyExchangeAlgorithm = Algorithms[AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME];
            _DefaultSignatureAlgorithm = Algorithms[AsymmetricEcDsaAlgorithm.ALGORITHM_NAME];
        }

        /// <summary>
        /// An object for thread synchronization
        /// </summary>
        public static object SyncObject { get; } = new();

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
        /// Use the hybrid key exchange options?
        /// </summary>
        public static bool UseHybridKeyExchangeOptions
        {
            get => _UseHybridKeyExchangeOptions;
            set
            {
                lock (SyncObject) _UseHybridKeyExchangeOptions = value;
            }
        }

        /// <summary>
        /// Use the hybrid signature options?
        /// </summary>
        public static bool UseHybridSignatureOptions
        {
            get => _UseHybridSignatureOptions;
            set
            {
                lock (SyncObject) _UseHybridSignatureOptions = value;
            }
        }

        /// <summary>
        /// Key exchange algorithms
        /// </summary>
        public static IEnumerable<IAsymmetricAlgorithm> KeyExchangeAlgorithms
            => from algo in Algorithms.Values
               where algo.Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.KeyExchange)
               select algo;

        /// <summary>
        /// Signature algorithms
        /// </summary>
        public static IEnumerable<IAsymmetricAlgorithm> SignatureAlgorithms
            => from algo in Algorithms.Values
               where algo.Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.Signature)
               select algo;

        /// <summary>
        /// Pre-quantum algorithms
        /// </summary>
        public static IEnumerable<IAsymmetricAlgorithm> PreQuantum
            => from algo in Algorithms.Values
               where !algo.IsPostQuantum
               select algo;

        /// <summary>
        /// Pre-quantum key exchange algorithms
        /// </summary>
        public static IEnumerable<IAsymmetricAlgorithm> PreQuantumKeyExchange
            => from algo in Algorithms.Values
               where !algo.IsPostQuantum &&
                algo.Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.KeyExchange)
               select algo;

        /// <summary>
        /// Pre-quantum signature algorithms
        /// </summary>
        public static IEnumerable<IAsymmetricAlgorithm> PreQuantumSignature
            => from algo in Algorithms.Values
               where !algo.IsPostQuantum &&
                algo.Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.Signature)
               select algo;

        /// <summary>
        /// Post-quantum algorithms
        /// </summary>
        public static IEnumerable<IAsymmetricAlgorithm> PostQuantum
            => from algo in Algorithms.Values
               where algo.IsPostQuantum
               select algo;

        /// <summary>
        /// Post-quantum key exchange algorithms
        /// </summary>
        public static IEnumerable<IAsymmetricAlgorithm> PostQuantumKeyExchange
            => from algo in Algorithms.Values
               where algo.IsPostQuantum &&
                algo.Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.KeyExchange)
               select algo;

        /// <summary>
        /// Post-quantum signature algorithms
        /// </summary>
        public static IEnumerable<IAsymmetricAlgorithm> PostQuantumSignature
            => from algo in Algorithms.Values
               where algo.IsPostQuantum &&
                algo.Usages.ContainsAnyFlag(AsymmetricAlgorithmUsages.Signature)
               select algo;

        /// <summary>
        /// Create a new key pair
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Private key</returns>
        public static IAsymmetricPrivateKey CreateKeyPair(CryptoOptions options)
        {
            try
            {
                if (options.AsymmetricAlgorithm is null) throw new ArgumentException("Missing asymmetric algorithm name", nameof(options));
                return GetAlgorithm(options.AsymmetricAlgorithm).CreateKeyPair(options);
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
        /// Create a new key pair for key exchange
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Private key</returns>
        public static IKeyExchangePrivateKey CreateKeyExchangeKeyPair(CryptoOptions? options = null)
        {
            try
            {
                options = GetDefaultKeyExchangeOptions(options?.GetCopy());
                return (IKeyExchangePrivateKey)GetAlgorithm(options.AsymmetricAlgorithm!).CreateKeyPair(options);
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
        /// Create a new key pair for signature
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Private key</returns>
        public static ISignaturePrivateKey CreateSignatureKeyPair(CryptoOptions? options = null)
        {
            try
            {
                options = GetDefaultSignatureOptions(options?.GetCopy());
                return (ISignaturePrivateKey)GetAlgorithm(options.AsymmetricAlgorithm!).CreateKeyPair(options);
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
        /// Get the default key exchange options used by the asymmetric helper
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions GetDefaultKeyExchangeOptions(CryptoOptions? options = null)
        {
            try
            {
                if (options is null)
                {
                    options = DefaultKeyExchangeAlgorithm.DefaultOptions;
                }
                else
                {
                    if (options.AsymmetricAlgorithm is null)
                    {
                        options.AsymmetricAlgorithm = DefaultKeyExchangeAlgorithm.Name;
                        options.AsymmetricKeyBits = DefaultKeyExchangeAlgorithm.DefaultKeySize;
                        options.AsymmetricAlgorithmOptions = DefaultKeyExchangeAlgorithm.DefaultAlgorithmOptions;
                    }
                }
                if (UseHybridKeyExchangeOptions) options = HybridAlgorithmHelper.GetKeyExchangeOptions(options);
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
        /// Get the default signature options used by the asymmetric helper
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions GetDefaultSignatureOptions(CryptoOptions? options = null)
        {
            try
            {
                if (options is null)
                {
                    options = DefaultSignatureAlgorithm.DefaultOptions;
                }
                else
                {
                    if (options.AsymmetricAlgorithm is null)
                    {
                        options.AsymmetricAlgorithm = DefaultSignatureAlgorithm.Name;
                        options.AsymmetricKeyBits = DefaultSignatureAlgorithm.DefaultKeySize;
                        options.AsymmetricAlgorithmOptions = DefaultSignatureAlgorithm.DefaultAlgorithmOptions;
                    }
                }
                if (options.HashAlgorithm is null) HashHelper.GetDefaultOptions(options);
                if (UseHybridSignatureOptions) options = HybridAlgorithmHelper.GetSignatureOptions(options);
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
            => Algorithms.Values.FirstOrDefault(a => a.Value == value) ?? throw new ArgumentException("Invalid algorithm", nameof(value));
    }
}
