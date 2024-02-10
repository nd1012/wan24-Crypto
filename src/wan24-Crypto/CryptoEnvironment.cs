using wan24.Crypto.Authentication;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto environment configuration
    /// </summary>
    public static partial class CryptoEnvironment
    {
        /// <summary>
        /// Apply a configuration
        /// </summary>
        /// <param name="options"><see cref="Options"/></param>
        public static void Configure(Options options)
        {
            if (options.DefaultKeyExchangeAlgorithm is not null) AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricHelper.GetAlgorithm(options.DefaultKeyExchangeAlgorithm);
            if (options.DefaultSignatureAlgorithm is not null) AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricHelper.GetAlgorithm(options.DefaultSignatureAlgorithm);
            options.PKI?.EnableLocalPki();
            if (options.UseCryptoExceptionDelay)
            {
                if (options.CryptoExceptionDelay.HasValue) CryptographicException.Delay = options.CryptoExceptionDelay;
            }
            else
            {
                CryptographicException.Delay = null;
            }
            if (options.DefaultMaximumAge.HasValue) CryptoOptions.DefaultMaximumAge = options.DefaultMaximumAge;
            if (options.DefaultMaximumTimeOffset.HasValue) CryptoOptions.DefaultMaximumTimeOffset = options.DefaultMaximumTimeOffset;
            if (options.DefaultPrivateKeysStore is not null) CryptoOptions.DefaultPrivateKeysStore = options.DefaultPrivateKeysStore;
            if (options.DefaultFlags.HasValue) CryptoOptions.DefaultFlags = options.DefaultFlags.Value;
            if (options.DefaultFlagsIncluded.HasValue) CryptoOptions.DefaultFlagsIncluded = options.DefaultFlagsIncluded.Value;
            if (options.DefaultEncryptionPasswordPreProcessor is not null) CryptoOptions.DefaultEncryptionPasswordPreProcessor = options.DefaultEncryptionPasswordPreProcessor;
            if (options.DefaultEncryptionPasswordAsyncPreProcessor is not null) CryptoOptions.DefaultEncryptionPasswordAsyncPreProcessor = options.DefaultEncryptionPasswordAsyncPreProcessor;
            if (options.DefaultEncryptionAlgorithm is not null) EncryptionHelper.DefaultAlgorithm = EncryptionHelper.GetAlgorithm(options.DefaultEncryptionAlgorithm);
            if (options.DefaultHashAlgorithm is not null) HashHelper.DefaultAlgorithm = HashHelper.GetAlgorithm(options.DefaultHashAlgorithm);
            if (options.CounterKeyExchangeAlgorithm is not null) HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricHelper.GetAlgorithm(options.CounterKeyExchangeAlgorithm);
            if (options.CounterSignatureAlgorithm is not null) HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricHelper.GetAlgorithm(options.CounterSignatureAlgorithm);
            if (options.CounterKdfAlgorithm is not null) HybridAlgorithmHelper.KdfAlgorithm = KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm);
            if (options.CounterMacAlgorithm is not null) HybridAlgorithmHelper.MacAlgorithm = MacHelper.GetAlgorithm(options.CounterMacAlgorithm);
            if (options.DefaultPakeOptions is not null) Pake.DefaultOptions = options.DefaultPakeOptions;
            if (options.DefaultPakeCryptoOptions is not null) Pake.DefaultCryptoOptions = options.DefaultPakeCryptoOptions;
            if (options.SkipPakeSignatureKeyValidation.HasValue) Pake.SkipSignatureKeyValidation = options.SkipPakeSignatureKeyValidation.Value;
            if (options.RandomGenerator is not null) RND.Generator = options.RandomGenerator;
            if (options.SeedConsumer is not null) RND.SeedConsumer = options.SeedConsumer;
            if (options.UseDevRandom.HasValue) RND.UseDevRandom = options.UseDevRandom.Value;
            if (options.RequireDevRandom.HasValue) RND.RequireDevRandom = options.RequireDevRandom.Value;
            if (options.DevRandomPool is not null) RND.DevRandomPool = options.DevRandomPool;
            if (options.AutoRngSeeding.HasValue) RND.AutoRngSeeding = options.AutoRngSeeding.Value;
            if (options.FillRandomBytes is not null) RND.FillBytes = options.FillRandomBytes;
            if (options.FillRandomBytesAsync is not null) RND.FillBytesAsync = options.FillRandomBytesAsync;
            if (options.DefaultEncryptTimeout.HasValue) SecureValue.DefaultEncryptTimeout = options.DefaultEncryptTimeout.Value;
            if (options.DefaultRecryptTimeout.HasValue) SecureValue.DefaultRecryptTimeout = options.DefaultRecryptTimeout.Value;
            if (options.DefaultServerPublicKeyValidator is not null) ClientAuth.DefaultServerPublicKeyValidator = options.DefaultServerPublicKeyValidator;
            if (options.DefaultClientAuthOptions is not null) ClientAuthOptions.DefaultOptions = options.DefaultClientAuthOptions;
            if (options.DefaultPakeClientAuthOptions is not null) PakeClientAuthOptions.DefaultOptions = options.DefaultPakeClientAuthOptions;
            if (options.AsymmetricKeySigner is not null) AsymmetricKeySigner.Instance = options.AsymmetricKeySigner;
            if (options.AsymmetricKeySignerService is not null) AsymmetricKeySignerService.Instance = options.AsymmetricKeySignerService;
            if (options.ProcessScopeKey is not null) ValueProtection.ProcessScopeKey = options.ProcessScopeKey;
            if (options.UserScopeKey is not null) ValueProtection.UserScopeKey = options.UserScopeKey;
            if (options.SystemScopeKey is not null) ValueProtection.SystemScopeKey = options.SystemScopeKey;
            if (options.PbKdf2HashAlgorithm is not null) KdfPbKdf2Options.DefaultHashAlgorithm = options.PbKdf2HashAlgorithm;
            if (options.Sp800_108HashAlgorithm is not null) KdfSp800_801HmacKbKdfOptions.DefaultHashAlgorithm = options.Sp800_108HashAlgorithm;
            if (options.ValueProtectionTpmMacAlgorithm is not null) ValueProtectionKeys.TpmMacAlgorithmName = options.ValueProtectionTpmMacAlgorithm;
            if (options.ValueProtectionMacAlgorithm is not null) ValueProtectionKeys.MacAlgorithmName = options.ValueProtectionMacAlgorithm;
            if (options.StrictPostQuantum.HasValue) CryptoHelper.ForcePostQuantumSafety(options.StrictPostQuantum.Value);
            if (options.RemoveUnsupportedAlgorithms) CryptoHelper.RemoveUnsupportedAlgorithms(options.UpdateDefaultOptionsAfterRemoveUnsupportedAlgorithms);
            if (options.DefaultAllowedValidationDomains is not null) SignedAttributes.ValidationOptions.DefaultAllowedValidationDomains = options.DefaultAllowedValidationDomains;
            if (options.DefaultDeniedValidationDomains is not null) SignedAttributes.ValidationOptions.DefaultDeniedValidationDomains = options.DefaultDeniedValidationDomains;
            if (options.DefaultAllowedKeyValidationApiUris is not null) SignedAttributes.ValidationOptions.DefaultAllowedKeyValidationApiUris = options.DefaultAllowedKeyValidationApiUris;
            if (options.DefaultDeniedKeyValidationApiUris is not null) SignedAttributes.ValidationOptions.DefaultDeniedKeyValidationApiUris = options.DefaultDeniedKeyValidationApiUris;
            if (options.DefaultAllowedUsages is not null) SignedAttributes.ValidationOptions.DefaultAllowedUsages = options.DefaultAllowedUsages;
            if (options.DefaultDeniedUsages is not null) SignedAttributes.ValidationOptions.DefaultDeniedUsages = options.DefaultDeniedUsages;
            if (options.DefaultRequiredUsages is not null) SignedAttributes.ValidationOptions.DefaultRequiredUsages = options.DefaultRequiredUsages;
            if (options.DefaultRequireKeyExchangeCounterKey.HasValue) SignedAttributes.ValidationOptions.DefaultRequireKeyExchangeCounterKey = options.DefaultRequireKeyExchangeCounterKey.Value;
            if (options.DefaultRequireSignatureCounterKey.HasValue) SignedAttributes.ValidationOptions.DefaultRequireSignatureCounterKey = options.DefaultRequireSignatureCounterKey.Value;
            if (options.DefaultRequireCipherSuite.HasValue) SignedAttributes.ValidationOptions.DefaultRequireCipherSuite = options.DefaultRequireCipherSuite.Value;
            if (options.DefaultRequireSerial.HasValue) SignedAttributes.ValidationOptions.DefaultRequireSerial = options.DefaultRequireSerial.Value;
            if (options.AdditionalValidation is not null) SignedAttributes.AdditionalValidation = options.AdditionalValidation;
            if (options.AdditionalValidationAsync is not null) SignedAttributes.AdditionalValidationAsync = options.AdditionalValidationAsync;
        }

        /// <summary>
        /// Singleton PKI
        /// </summary>
        public static SignedPkiStore? PKI { get; set; }

        /// <summary>
        /// Singleton private key suite store
        /// </summary>
        public static PrivateKeySuiteStore? PrivateKeysStore { get; set; }

        /// <summary>
        /// Singleton random data generator service
        /// </summary>
        public static RandomDataGenerator? RandomGenerator { get; set; }

        /// <summary>
        /// PAKE authentication client
        /// </summary>
        public static FastPakeAuthClient? PakeAuthClient { get; set; }

        /// <summary>
        /// PAKE authentication server
        /// </summary>
        public static FastPakeAuthServer? PakeAuthServer { get; set; }

        /// <summary>
        /// Asymmetric key pool (will be the default for <see cref="ServerAuthOptions.PfsKeyPool"/>)
        /// </summary>
        public static IAsymmetricKeyPool? AsymmetricKeyPool { get; set; }

        /// <summary>
        /// PAKE authentication record pool (will be the default for <see cref="PakeServerAuthOptions.AuthRecordPool"/>)
        /// </summary>
        public static IPakeAuthRecordPool? PakeAuthRecordPool { get; set; }
    }
}
