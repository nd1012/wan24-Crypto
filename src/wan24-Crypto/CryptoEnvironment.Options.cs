using System.Collections.ObjectModel;
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
            /// Use a timespan for a random <see cref="CryptographicException"/> delay?
            /// </summary>
            public bool UseCryptoExceptionDelay { get; set; } = true;

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
            public IRng? RandomGenerator { get; set; } = CryptoEnvironment.RandomGenerator;

            /// <summary>
            /// RNG seed consumer
            /// </summary>
            public ISeedConsumer? SeedConsumer { get; set; }

            /// <summary>
            /// Use <c>/dev/random</c>, if available?
            /// </summary>
            public bool? UseDevRandom { get; set; }

            /// <summary>
            /// Require <c>/dev/random</c> (will throw, if not available)?
            /// </summary>
            public bool? RequireDevRandom { get; set; }

            /// <summary>
            /// <c>/dev/random</c> readable stream pool
            /// </summary>
            public DevRandomStreamPool? DevRandomPool { get; set; }

            /// <summary>
            /// Automatic RNG seeding flags
            /// </summary>
            public RngSeedingTypes? AutoRngSeeding { get; set; }

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

            /// <summary>
            /// <see cref="AsymmetricPublicKeySigningRequest"/> signer
            /// </summary>
            public AsymmetricKeySigner? AsymmetricKeySigner { get; set; }

            /// <summary>
            /// <see cref="AsymmetricPublicKeySigningRequest"/> signer service
            /// </summary>
            public AsymmetricKeySignerService? AsymmetricKeySignerService { get; set; }

            /// <summary>
            /// Process scope key for <see cref="ValueProtection"/>
            /// </summary>
            public ISecureValue? ProcessScopeKey { get; set; }

            /// <summary>
            /// User scope key for <see cref="ValueProtection"/>
            /// </summary>
            public ISecureValue? UserScopeKey { get; set; }

            /// <summary>
            /// System scope key for <see cref="ValueProtection"/>
            /// </summary>
            public ISecureValue? SystemScopeKey { get; set; }

            /// <summary>
            /// Default PBKDF#2 hash algorithm name for the <see cref="KdfPbKdf2Options"/>
            /// </summary>
            public string? PbKdf2HashAlgorithm { get; set; }

            /// <summary>
            /// Default SP800-108 hash algorithm name for the <see cref="KdfSp800_801HmacKbKdfOptions"/>
            /// </summary>
            public string? Sp800_108HashAlgorithm { get; set; }

            /// <summary>
            /// Force strict post quantum safety?
            /// </summary>
            public bool? StrictPostQuantum { get; set; }

            /// <summary>
            /// TPM MAC algorithm name for <see cref="ValueProtectionKeys"/>
            /// </summary>
            public string? ValueProtectionTpmMacAlgorithm { get; set; }

            /// <summary>
            /// MAC algorithm name for <see cref="ValueProtectionKeys"/>
            /// </summary>
            public string? ValueProtectionMacAlgorithm { get; set; }

            /// <summary>
            /// Remove unsupported algorithms?
            /// </summary>
            public bool RemoveUnsupportedAlgorithms { get; set; }

            /// <summary>
            /// Update default options after unsupported algorithms have been removed?
            /// </summary>
            public bool UpdateDefaultOptionsAfterRemoveUnsupportedAlgorithms { get; set; }

            /// <summary>
            /// Default encryption password pre-processor
            /// </summary>
            public CryptoOptions.EncryptionPasswordPreProcessor_Delegate? DefaultEncryptionPasswordPreProcessor { get; set; }

            /// <summary>
            /// Default encryption password pre-processor
            /// </summary>
            public CryptoOptions.AsyncEncryptionPasswordPreProcessor_Delegate? DefaultEncryptionPasswordAsyncPreProcessor { get; set; }

            /// <summary>
            /// Default allowed validation domains (signed attribute validation)
            /// </summary>
            public ReadOnlyCollection<string>? DefaultAllowedValidationDomains { get; set; }

            /// <summary>
            /// Default denied validation domains (signed attribute validation)
            /// </summary>
            public ReadOnlyCollection<string>? DefaultDeniedValidationDomains { get; set; }

            /// <summary>
            /// Default allowed key validation API URIs (signed attribute validation)
            /// </summary>
            public ReadOnlyCollection<string>? DefaultAllowedKeyValidationApiUris { get; set; }

            /// <summary>
            /// Default denied key validation API URIs (signed attribute validation)
            /// </summary>
            public ReadOnlyCollection<string>? DefaultDeniedKeyValidationApiUris { get; set; }

            /// <summary>
            /// Default allowed key usages (signed attribute validation)
            /// </summary>
            public AsymmetricAlgorithmUsages? DefaultAllowedUsages { get; set; }

            /// <summary>
            /// Default denied key usages (signed attribute validation)
            /// </summary>
            public AsymmetricAlgorithmUsages? DefaultDeniedUsages { get; set; }

            /// <summary>
            /// Default required key usages (signed attribute validation)
            /// </summary>
            public AsymmetricAlgorithmUsages? DefaultRequiredUsages { get; set; }

            /// <summary>
            /// Default require a key exchange counter key? (signed attribute validation)
            /// </summary>
            public bool? DefaultRequireKeyExchangeCounterKey { get; set; }

            /// <summary>
            /// Default require a signature counter key? (signed attribute validation)
            /// </summary>
            public bool? DefaultRequireSignatureCounterKey { get; set; }

            /// <summary>
            /// Default require a cipher suite (<see cref="CryptoOptions"/>)? (signed attribute validation)
            /// </summary>
            public bool? DefaultRequireCipherSuite { get; set; }

            /// <summary>
            /// Default require a public key revision serial number? (signed attribute validation)
            /// </summary>
            public bool? DefaultRequireSerial { get; set; }

            /// <summary>
            /// Additional attribute validator
            /// </summary>
            public SignedAttributes.Validate_Delegate? AdditionalValidation { get; set; }

            /// <summary>
            /// Additional attribute validator
            /// </summary>
            public SignedAttributes.ValidateAsync_Delegate? AdditionalValidationAsync { get; set; }

            /// <summary>
            /// Max. array length in serialized data in bytes
            /// </summary>
            public int? SignatureContainerMaxArrayLength { get; set; }

            /// <summary>
            /// Max. array length in serialized data in bytes
            /// </summary>
            public int? AsymmetricKeyMaxArrayLength { get; set; }

            /// <summary>
            /// Max. key exchange data length in bytes
            /// </summary>
            public int? MaxKeyExchangeDataLength { get; set; }

            /// <summary>
            /// Default password post-processor to use in <see cref="PasswordPostProcessor.Instance"/>
            /// </summary>
            public PasswordPostProcessor? DefaultPasswordPostProcessor { get; set; }

            /// <summary>
            /// Default <see cref="RngStream"/> to set to <see cref="RngStream.Instance"/>
            /// </summary>
            public RngStream? DefaultRngStream { get; set; }

            /// <summary>
            /// Denied asymmetric algorithms (key is the algorithm value, value the algorithm name)
            /// </summary>
            public Dictionary<int, string>? DeniedAsymmetric { get; set; }

            /// <summary>
            /// Denied encryption algorithms (key is the algorithm value, value the algorithm name)
            /// </summary>
            public Dictionary<int, string>? DeniedEncryption { get; set; }

            /// <summary>
            /// Capacity for key pools of all key sizes of all available asymmetric algorithms
            /// </summary>
            public int? AsymmericKeyPoolsCapacity { get; set; }

            /// <summary>
            /// Denied elliptic curve names
            /// </summary>
            public string[]? DeniedEllipticCurveNames { get; set; }

            /// <summary>
            /// Password post-processors to apply in a sequential chain (set to <see cref="PasswordPostProcessor.Instance"/>)
            /// </summary>
            public PasswordPostProcessor[]? PasswordPostProcessors { get; set; }

            /// <summary>
            /// If to use <see cref="PasswordPostProcessors"/> in the <see cref="CryptoOptions"/>
            /// </summary>
            public bool UsePasswordPostProcessorsInCryptoOptions { get; set; }
        }
    }
}
