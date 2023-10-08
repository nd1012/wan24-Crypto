using wan24.Crypto.Authentication;

namespace wan24.Crypto
{
    // Options
    public static partial class CryptoEnvironment
    {
        /// <summary>
        /// Options
        /// </summary>
        public sealed class Options
        {
            /// <summary>
            /// Constructor
            /// </summary>
            public Options() { }

            /// <summary>
            /// Default key exchange algorithm
            /// </summary>
            public string? DefaultKeyExchangeAlgorithm { get; set; }

            /// <summary>
            /// Default signature algorithm
            /// </summary>
            public string? DefaultSignatureAlgorithm { get; set; }

            /// <summary>
            /// PKI
            /// </summary>
            public SignedPkiStore? PKI { get; set; } = CryptoEnvironment.PKI;

            /// <summary>
            /// Timespan for a random <see cref="CryptographicException"/> delay
            /// </summary>
            public TimeSpan? CryptoExceptionDelay { get; set; }

            /// <summary>
            /// Default maximum cipher data age for decryption
            /// </summary>
            public TimeSpan? DefaultMaximumAge { get; set; }

            /// <summary>
            /// Default maximum time offset for decryption
            /// </summary>
            public TimeSpan? DefaultMaximumTimeOffset { get; set; }

            /// <summary>
            /// Default private key suite store for en-/decryption
            /// </summary>
            public PrivateKeySuiteStore? DefaultPrivateKeysStore { get; set; } = PrivateKeysStore;

            /// <summary>
            /// Default <see cref="CryptoOptions"/> flags (will be used for requirements, too)
            /// </summary>
            public CryptoFlags? DefaultFlags { get; set; }

            /// <summary>
            /// Default encryption algorithm
            /// </summary>
            public string? DefaultEncryptionAlgorithm { get; set; }

            /// <summary>
            /// Default hash algorithm
            /// </summary>
            public string? DefaultHashAlgorithm { get; set; }

            /// <summary>
            /// Counter key exchange algorithm
            /// </summary>
            public string? CounterKeyExchangeAlgorithm { get; set; }

            /// <summary>
            /// Counter signature algorithm
            /// </summary>
            public string? CounterSignatureAlgorithm { get; set; }

            /// <summary>
            /// Counter KDF algorithm
            /// </summary>
            public string? CounterKdfAlgorithm { get; set; }

            /// <summary>
            /// Counter MAC algorithm
            /// </summary>
            public string? CounterMacAlgorithm { get; set; }

            /// <summary>
            /// Default KDF algorithm
            /// </summary>
            public string? DefaultKdfAlgorithm { get; set; }

            /// <summary>
            /// Default MAC algorithm
            /// </summary>
            public string? DefaultMacAlgorithm { get; set; }

            /// <summary>
            /// Default PAKE options (should/will be cleared!)
            /// </summary>
            public CryptoOptions? DefaultPakeOptions { get; set; }

            /// <summary>
            /// Default PAKE options for encryption (should/will be cleared!)
            /// </summary>
            public CryptoOptions? DefaultPakeCryptoOptions { get; set; }

            /// <summary>
            /// Skip the PAKE signature key validation (KDF) during authentication?
            /// </summary>
            public bool? SkipPakeSignatureKeyValidation { get; set; }

            /// <summary>
            /// Random data generator service
            /// </summary>
            public RandomDataGenerator? RandomGenerator { get; set; } = CryptoEnvironment.RandomGenerator;

            /// <summary>
            /// Use <c>/dev/urandom</c>, if available?
            /// </summary>
            public bool? UseDevUrandom { get; set; }

            /// <summary>
            /// Require <c>/dev/urandom</c> (will throw, if not available)?
            /// </summary>
            public bool? RequireDevUrandom { get; set; }

            /// <summary>
            /// Delegate for filling a buffer with random bytes
            /// </summary>
            public RND.RNG_Delegate? FillRandomBytes { get; set; }

            /// <summary>
            /// Delegate for filling a buffer with random bytes
            /// </summary>
            public RND.RNGAsync_Delegate? FillRandomBytesAsync { get; set; }

            /// <summary>
            /// Default encrypt timeout for <see cref="SecureValue"/>
            /// </summary>
            public TimeSpan? DefaultEncryptTimeout { get; set; }

            /// <summary>
            /// Default re-crypt timeout for <see cref="SecureValue"/>
            /// </summary>
            public TimeSpan? DefaultRecryptTimeout { get; set; }

            /// <summary>
            /// Default public server key validator (<see cref="ClientAuth"/>)
            /// </summary>
            public ClientAuth.ServerPublicKeyValidation_Delegate? DefaultServerPublicKeyValidator { get; set; }

            /// <summary>
            /// Default <see cref="ClientAuth"/> options (will be cloned for delivery)
            /// </summary>
            public ClientAuthOptions? DefaultClientAuthOptions { get; set; }

            /// <summary>
            /// Default <see cref="PakeClientAuthOptions"/> options (will be cloned for delivery; will be disposed!)
            /// </summary>
            public PakeClientAuthOptions? DefaultPakeClientAuthOptions { get; set; }

            /// <summary>
            /// Default for <see cref="CryptoOptions.DefaultFlagsIncluded"/>
            /// </summary>
            public bool? DefaultFlagsIncluded { get; set; }
        }
    }
}
