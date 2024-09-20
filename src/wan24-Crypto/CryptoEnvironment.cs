using System.Security.Cryptography;
using wan24.Core;
using wan24.Crypto.Authentication;
using static wan24.Core.TranslationHelper;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto environment configuration
    /// </summary>
    public static partial class CryptoEnvironment
    {
        /// <summary>
        /// All enabled algorithms
        /// </summary>
        public static IEnumerable<ICryptoAlgorithm> AllAlgorithms
        {
            get
            {
                foreach (ICryptoAlgorithm algo in AsymmetricHelper.Algorithms.Values)
                    yield return algo;
                foreach (ICryptoAlgorithm algo in EncryptionHelper.Algorithms.Values)
                    yield return algo;
                foreach (ICryptoAlgorithm algo in HashHelper.Algorithms.Values)
                    yield return algo;
                foreach (ICryptoAlgorithm algo in MacHelper.Algorithms.Values)
                    yield return algo;
                foreach (ICryptoAlgorithm algo in KdfHelper.Algorithms.Values)
                    yield return algo;
            }
        }

        /// <summary>
        /// Overall state of the crypto environment
        /// </summary>
        public static IEnumerable<Status> State
        {
            get
            {
                // RNG
                yield return new(__("/dev/random"), RND.HasDevRandom, __("If /dev/random is available"), "RNG");
                yield return new(__("Use /dev/random"), RND.UseDevRandom, __("If /dev/random is being used"), "RNG");
                yield return new(__("Require /dev/random"), RND.RequireDevRandom, __("If /dev/random is required"), "RNG");
                yield return new(__("/dev/random pool"), RND.DevRandomPool is not null, __("If a /dev/random pool is available"), "RNG");
                yield return new(__("Seed consumer"), RND.SeedConsumer?.GetType().ToString() ?? __("none"), __("The CLR type of the seed consumer"), "RNG");
                yield return new(__("Auto seeding"), RND.AutoRngSeeding, __("Automatic RNG seeding type"), "RNG");
                yield return new(__("RNG"), RND.Generator?.GetType().ToString() ?? (RND.UseDevRandom ? __("/dev/random") : typeof(RandomNumberGenerator).ToString()), __("The CLR type of the RNG"), "RNG");
                // Environment
                yield return new(__("PKI"), PKI?.GetType().ToString() ?? __("none"), __("The CLR type of the PKI"), __("Environment"));
                yield return new(__("Private key store"), PrivateKeysStore?.GetType().ToString() ?? __("none"), __("The CLR type of the private key store"), __("Environment"));
                yield return new(__("PAKE client"), PakeAuthClient?.GetType().ToString() ?? __("none"), __("The CLR type of the PAKE authentication client"), __("Environment"));
                yield return new(__("PAKE server"), PakeAuthServer?.GetType().ToString() ?? __("none"), __("The CLR type of the PAKE authentication server"), __("Environment"));
                yield return new(__("Key pool"), AsymmetricKeyPool?.GetType().ToString() ?? __("none"), __("The CLR type of the general asymmetric key pool"), __("Environment"));
                yield return new(__("PAKE record pool"), PakeAuthRecordPool?.GetType().ToString() ?? __("none"), __("The CLR type of the PAKE authentication record pool"), __("Environment"));
                yield return new(__("Enabled algorithms"), AllAlgorithms.Count(), __("Number of enabled crypto algorithms"), __("Environment"));
                // Asymmetric algorithms
                foreach (IAsymmetricAlgorithm algo in AsymmetricHelper.Algorithms.Values)
                    foreach (Status status in algo.State)
                        yield return new(status.Name, status.State, status.Description, $"{__("Asymmetric")}\\{algo.DisplayName.Replace('\\', '/')}");
                // Encryption algorithms
                foreach (EncryptionAlgorithmBase algo in EncryptionHelper.Algorithms.Values)
                    foreach (Status status in algo.State)
                        yield return new(status.Name, status.State, status.Description, $"{__("Encryption")}\\{algo.DisplayName.Replace('\\', '/')}");
                // MAC algorithms
                foreach (MacAlgorithmBase algo in MacHelper.Algorithms.Values)
                    foreach (Status status in algo.State)
                        yield return new(status.Name, status.State, status.Description, $"{__("MAC")}\\{algo.DisplayName.Replace('\\', '/')}");
                // Hash algorithms
                foreach (HashAlgorithmBase algo in HashHelper.Algorithms.Values)
                    foreach (Status status in algo.State)
                        yield return new(status.Name, status.State, status.Description, $"{__("Hash")}\\{algo.DisplayName.Replace('\\', '/')}");
                // KDF algorithms
                foreach (KdfAlgorithmBase algo in KdfHelper.Algorithms.Values)
                    foreach (Status status in algo.State)
                        yield return new(status.Name, status.State, status.Description, $"{__("KDF")}\\{algo.DisplayName.Replace('\\', '/')}");
                // PAKE servers
                yield return new(__("PAKE servers"), FastPakeAuthServerTable.Servers.Count, __("Number of fast PAKE authentication servers"), __("PAKE servers"));
                foreach (FastPakeAuthServer server in FastPakeAuthServerTable.Servers.Values)
                    foreach (Status status in server.State)
                        yield return new(status.Name, status.State, status.Description, $"{__("PAKE servers")}\\{(server.Name ?? server.GUID).Replace('\\', '/')}");
                // Secure values
                yield return new(__("Secure values"), SecureValueTable.Values.Count, __("Number of secure values"), __("Secure values"));
                foreach (SecureValue value in SecureValueTable.Values.Values)
                    foreach (Status status in value.State)
                        yield return new(status.Name, status.State, status.Description, $"{__("Secure values")}\\{(value.Name ?? value.GUID).Replace('\\', '/')}");
            }
        }

        /// <summary>
        /// Apply a configuration
        /// </summary>
        /// <param name="options"><see cref="Options"/></param>
        public static void Configure(in Options options)
        {
            // Default algorithms
            if (options.DefaultKeyExchangeAlgorithm is not null) AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricHelper.GetAlgorithm(options.DefaultKeyExchangeAlgorithm);
            if (options.DefaultSignatureAlgorithm is not null) AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricHelper.GetAlgorithm(options.DefaultSignatureAlgorithm);
            if (options.DefaultEncryptionAlgorithm is not null) EncryptionHelper.DefaultAlgorithm = EncryptionHelper.GetAlgorithm(options.DefaultEncryptionAlgorithm);
            if (options.DefaultHashAlgorithm is not null) HashHelper.DefaultAlgorithm = HashHelper.GetAlgorithm(options.DefaultHashAlgorithm);
            if (options.PbKdf2HashAlgorithm is not null) KdfPbKdf2Options.DefaultHashAlgorithm = options.PbKdf2HashAlgorithm;
            if (options.Sp800_108HashAlgorithm is not null) KdfSp800_801HmacKbKdfOptions.DefaultHashAlgorithm = options.Sp800_108HashAlgorithm;
            if (options.ValueProtectionTpmMacAlgorithm is not null) ValueProtectionKeys.TpmMacAlgorithmName = options.ValueProtectionTpmMacAlgorithm;
            if (options.ValueProtectionMacAlgorithm is not null) ValueProtectionKeys.MacAlgorithmName = options.ValueProtectionMacAlgorithm;
            // Hybrid default algorithms
            if (options.CounterKeyExchangeAlgorithm is not null) HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricHelper.GetAlgorithm(options.CounterKeyExchangeAlgorithm);
            if (options.CounterSignatureAlgorithm is not null) HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricHelper.GetAlgorithm(options.CounterSignatureAlgorithm);
            if (options.CounterKdfAlgorithm is not null) HybridAlgorithmHelper.KdfAlgorithm = KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm);
            if (options.CounterMacAlgorithm is not null) HybridAlgorithmHelper.MacAlgorithm = MacHelper.GetAlgorithm(options.CounterMacAlgorithm);
            // Crypto options
            if (options.DefaultMaximumAge.HasValue) CryptoOptions.DefaultMaximumAge = options.DefaultMaximumAge;
            if (options.DefaultMaximumTimeOffset.HasValue) CryptoOptions.DefaultMaximumTimeOffset = options.DefaultMaximumTimeOffset;
            if (options.DefaultPrivateKeysStore is not null) CryptoOptions.DefaultPrivateKeysStore = options.DefaultPrivateKeysStore;
            if (options.DefaultFlags.HasValue) CryptoOptions.DefaultFlags = options.DefaultFlags.Value;
            if (options.DefaultFlagsIncluded.HasValue) CryptoOptions.DefaultFlagsIncluded = options.DefaultFlagsIncluded.Value;
            if (options.DefaultEncryptionPasswordPreProcessor is not null) CryptoOptions.DefaultEncryptionPasswordPreProcessor = options.DefaultEncryptionPasswordPreProcessor;
            if (options.DefaultEncryptionPasswordAsyncPreProcessor is not null) CryptoOptions.DefaultEncryptionPasswordAsyncPreProcessor = options.DefaultEncryptionPasswordAsyncPreProcessor;
            if (options.DefaultMaxCipherDataLength.HasValue) CryptoOptions.DefaultMaxCipherDataLength = options.DefaultMaxCipherDataLength.Value;
            // PAKE
            if (options.DefaultPakeOptions is not null) Pake.DefaultOptions = options.DefaultPakeOptions;
            if (options.DefaultPakeCryptoOptions is not null) Pake.DefaultCryptoOptions = options.DefaultPakeCryptoOptions;
            if (options.SkipPakeSignatureKeyValidation.HasValue) Pake.SkipSignatureKeyValidation = options.SkipPakeSignatureKeyValidation.Value;
            // RNG
            if (options.RandomGenerator is not null) RND.Generator = options.RandomGenerator;
            if (options.SeedConsumer is not null) RND.SeedConsumer = options.SeedConsumer;
            if (options.UseDevRandom.HasValue) RND.UseDevRandom = options.UseDevRandom.Value;
            if (options.RequireDevRandom.HasValue) RND.RequireDevRandom = options.RequireDevRandom.Value;
            if (options.DevRandomPool is not null) RND.DevRandomPool = options.DevRandomPool;
            if (options.AutoRngSeeding.HasValue) RND.AutoRngSeeding = options.AutoRngSeeding.Value;
            if (options.FillRandomBytes is not null) RND.FillBytes = options.FillRandomBytes;
            if (options.FillRandomBytesAsync is not null) RND.FillBytesAsync = options.FillRandomBytesAsync;
            if (options.IvHelperRng is not null) IvHelper.RNG = options.IvHelperRng;
            if (options.KeyHelperRng is not null) KeyHelper.RNG = options.KeyHelperRng;
            // Entropy
            if (options.DefaultEntropyAlgorithm.HasValue) EntropyHelper.DefaultAlgorithm = (EntropyHelper.Algorithms)options.DefaultEntropyAlgorithm.Value;
            if (options.DefaultEntropyAlgorithms.HasValue) EntropyHelper.DefaultAlgorithms = (EntropyHelper.Algorithms)options.DefaultEntropyAlgorithms.Value;
            if (options.MinShannonBitEntropy.HasValue) EntropyHelper.MinShannonBitEntropy = options.MinShannonBitEntropy.Value;
            if (options.MinShannonByteEntropy.HasValue) EntropyHelper.MinShannonByteEntropy = options.MinShannonByteEntropy.Value;
            if (options.MinCustomEntropy.HasValue) EntropyHelper.MinCustomEntropy = options.MinCustomEntropy.Value;
            // Password helper
            if (options.MaxPasswordGeneratorTries.HasValue) PasswordHelper.MaxTries = options.MaxPasswordGeneratorTries.Value;
            if (options.DefaultPasswordGeneratorOptions.HasValue) PasswordHelper.DefaultOptions = options.DefaultPasswordGeneratorOptions.Value;
            if (options.DefaultPasswordGeneratorLength.HasValue) PasswordHelper.DefaultLength = options.DefaultPasswordGeneratorLength.Value;
            if (options.DefaultPasswordGeneratorLowerCase is not null) PasswordHelper.DefaultLowerCase = options.DefaultPasswordGeneratorLowerCase;
            if (options.DefaultPasswordGeneratorUpperCase is not null) PasswordHelper.DefaultUpperCase = options.DefaultPasswordGeneratorUpperCase;
            if (options.DefaultPasswordGeneratorNumeric is not null) PasswordHelper.DefaultNumeric = options.DefaultPasswordGeneratorNumeric;
            if (options.DefaultPasswordGeneratorSpecial is not null) PasswordHelper.DefaultSpecial = options.DefaultPasswordGeneratorSpecial;
            // Secure value
            if (options.DefaultEncryptTimeout.HasValue) SecureValue.DefaultEncryptTimeout = options.DefaultEncryptTimeout.Value;
            if (options.DefaultRecryptTimeout.HasValue) SecureValue.DefaultRecryptTimeout = options.DefaultRecryptTimeout.Value;
            // Authentication
            if (options.DefaultServerPublicKeyValidator is not null) ClientAuth.DefaultServerPublicKeyValidator = options.DefaultServerPublicKeyValidator;
            if (options.DefaultClientAuthOptions is not null) ClientAuthOptions.DefaultOptions = options.DefaultClientAuthOptions;
            if (options.DefaultPakeClientAuthOptions is not null) PakeClientAuthOptions.DefaultOptions = options.DefaultPakeClientAuthOptions;
            // Signature
            if (options.AsymmetricKeySigner is not null) AsymmetricKeySigner.Instance = options.AsymmetricKeySigner;
            if (options.AsymmetricKeySignerService is not null) AsymmetricKeySignerService.Instance = options.AsymmetricKeySignerService;
            // Value protection keys
            if (options.ProcessScopeKey is not null) ValueProtection.ProcessScopeKey = options.ProcessScopeKey;
            if (options.UserScopeKey is not null) ValueProtection.UserScopeKey = options.UserScopeKey;
            if (options.SystemScopeKey is not null) ValueProtection.SystemScopeKey = options.SystemScopeKey;
            // Signed attributes
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
            // Max. array lengths
            if (options.SignatureContainerMaxArrayLength.HasValue) SignatureContainer.MaxArrayLength = options.SignatureContainerMaxArrayLength.Value;
            if (options.AsymmetricKeyMaxArrayLength.HasValue) AsymmetricKeyBase.MaxArrayLength = options.AsymmetricKeyMaxArrayLength.Value;
            if (options.MaxKeyExchangeDataLength.HasValue) KeyExchangeDataContainer.MaxKeyExchangeDataLength = options.MaxKeyExchangeDataLength.Value;
            // Other
            if (options.UseCryptoExceptionDelay)
            {
                if (options.CryptoExceptionDelay.HasValue) CryptographicException.Delay = options.CryptoExceptionDelay;
            }
            else
            {
                CryptographicException.Delay = null;
            }
            if (options.DefaultPasswordPostProcessor is not null) PasswordPostProcessor.Instance = options.DefaultPasswordPostProcessor;
            if (options.DefaultRngStream is not null) RngStream.Instance = options.DefaultRngStream;
            // Final initialization
            if (options.DeniedAsymmetric is not null)
                foreach (KeyValuePair<int, string> kvp in options.DeniedAsymmetric)
                    DeniedAlgorithms.AddAsymmetricAlgorithm(kvp.Key, kvp.Value);
            if (options.DeniedEncryption is not null)
                foreach (KeyValuePair<int, string> kvp in options.DeniedEncryption)
                    DeniedAlgorithms.AddEncryptionAlgorithm(kvp.Key, kvp.Value);
            if (options.DeniedEllipticCurveNames is not null)
                foreach (string name in options.DeniedEllipticCurveNames)
                    EllipticCurves.DenyCurve(name);
            options.PKI?.EnableLocalPki();
            if (options.RemoveUnsupportedAlgorithms) CryptoHelper.RemoveUnsupportedAlgorithms(options.UpdateDefaultOptionsAfterRemoveUnsupportedAlgorithms);
            if (options.StrictPostQuantum.HasValue) CryptoHelper.ForcePostQuantumSafety(options.StrictPostQuantum.Value);
            if (options.AsymmetricKeyPoolsCapacity.HasValue)
                foreach (IAsymmetricAlgorithm algo in AsymmetricHelper.Algorithms.Values.Where(a => a.EnsureAllowed(throwIfDenied: false)))
                    algo.CreateKeyPools(options.AsymmetricKeyPoolsCapacity.Value);
            if (options.PasswordPostProcessors is not null && options.PasswordPostProcessors.Length > 0)
            {
                PasswordPostProcessor.Instance = new PasswordPostProcessorChain(options.PasswordPostProcessors);
                if(options.UsePasswordPostProcessorsInCryptoOptions)
                {
                    CryptoOptions.DefaultEncryptionPasswordPreProcessor = PasswordPostProcessor.Instance.PreProcessEncryptionPassword;
                    CryptoOptions.DefaultEncryptionPasswordAsyncPreProcessor = PasswordPostProcessor.Instance.PreProcessEncryptionPasswordAsync;
                }
            }
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
