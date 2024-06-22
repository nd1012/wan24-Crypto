using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto app configuration (<see cref="AppConfig"/>; should be applied AFTER bootstrapping (<see cref="AppConfigAttribute.AfterBootstrap"/>); another 
    /// <see cref="CryptoEnvironment.Options"/> may be applied in addition)
    /// </summary>
    public class CryptoAppConfig : AppConfigBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public CryptoAppConfig() : base() { }

        /// <summary>
        /// Applied crypto app configuration
        /// </summary>
        [JsonIgnore]
        public static CryptoAppConfig? AppliedCryptoConfig { get; protected set; }

        /// <summary>
        /// Default algorithms
        /// </summary>
        public DefaultAlgorithms? Algorithms { get; set; }

        /// <summary>
        /// Default options
        /// </summary>
        public CryptoOptions? Options { get; set; }

        /// <summary>
        /// Skip the PAKE signature key validation (KDF) during authentication?
        /// </summary>
        public bool? SkipPakeSignatureKeyValidation { get; set; }

        /// <summary>
        /// RNG options
        /// </summary>
        public RngOptions? Rng { get; set; }

        /// <summary>
        /// Secure value options
        /// </summary>
        public SecureValueOptions? SecureValue { get; set; }

        /// <summary>
        /// Signed attributes options
        /// </summary>
        public SignedAttributesOptions? SignedAttributes { get; set; }

        /// <summary>
        /// Limits
        /// </summary>
        public Limitations? Limits { get; set; }

        /// <summary>
        /// Timespan for a random <see cref="CryptographicException"/> delay
        /// </summary>
        public TimeSpan? CryptoExceptionDelay { get; set; }

        /// <summary>
        /// Use a timespan for a random <see cref="CryptographicException"/> delay?
        /// </summary>
        public bool UseCryptoExceptionDelay { get; set; } = true;

        /// <summary>
        /// Remove unsupported algorithms?
        /// </summary>
        public bool RemoveUnsupportedAlgorithms { get; set; }

        /// <summary>
        /// Update default options after unsupported algorithms have been removed?
        /// </summary>
        public bool UpdateDefaultOptionsAfterRemoveUnsupportedAlgorithms { get; set; }

        /// <summary>
        /// Asymmetric key pool capacity for all allowed key sizes of all available asymmetric algorithms
        /// </summary>
        public int? AsymmetricKeyPoolsCapacity { get; set; }

        /// <summary>
        /// Password post-processor type names to apply in a sequential chain (need parameterless constructors)
        /// </summary>
        public string[]? PasswordPostProcessors { get; set; }//TODO Apply

        /// <summary>
        /// If to use <see cref="PasswordPostProcessors"/> in the <see cref="CryptoOptions"/>
        /// </summary>
        public bool UsePasswordPostProcessorsInCryptoOptions { get; set; }//TODO Apply

        /// <inheritdoc/>
        public sealed override void Apply()
        {
            if (SetApplied)
            {
                if (AppliedCryptoConfig is not null) throw new InvalidOperationException();
                AppliedCryptoConfig = this;
            }
            CryptoEnvironment.Options options = new();
            Apply(options);
            CryptoEnvironment.Configure(options);
        }

        /// <inheritdoc/>
        public sealed override async Task ApplyAsync(CancellationToken cancellationToken = default)
        {
            if (SetApplied)
            {
                if (AppliedCryptoConfig is not null) throw new InvalidOperationException();
                AppliedCryptoConfig = this;
            }
            CryptoEnvironment.Options options = new();
            await ApplyAsync(options, cancellationToken).DynamicContext();
            CryptoEnvironment.Configure(options);
        }

        /// <summary>
        /// Apply
        /// </summary>
        /// <param name="options">Options</param>
        protected virtual void Apply(in CryptoEnvironment.Options options)
        {
            Algorithms?.Apply(options);
            options.SkipPakeSignatureKeyValidation = SkipPakeSignatureKeyValidation;
            Options?.Apply(options);
            Rng?.Apply(options);
            SecureValue?.Apply(options);
            SignedAttributes?.Apply(options);
            Limits?.Apply(options);
            options.CryptoExceptionDelay = CryptoExceptionDelay;
            options.UseCryptoExceptionDelay = UseCryptoExceptionDelay;
            options.RemoveUnsupportedAlgorithms = RemoveUnsupportedAlgorithms;
            options.UpdateDefaultOptionsAfterRemoveUnsupportedAlgorithms = UpdateDefaultOptionsAfterRemoveUnsupportedAlgorithms;
            options.AsymmericKeyPoolsCapacity = AsymmetricKeyPoolsCapacity;
            if (PasswordPostProcessors is not null)
            {
                List<PasswordPostProcessor> ppr = [];
                Type type;
                foreach(string typeName in PasswordPostProcessors)
                {
                    type = TypeHelper.Instance.GetType(typeName, throwOnError: true)
                        ?? throw new InvalidDataException("Invalid/unknown type name in crypto app config at PasswordPostProcessors");
                    if (!type.CanConstruct() || !typeof(PasswordPostProcessor).IsAssignableFrom(type))
                        throw new InvalidDataException($"Invalid type {type} in crypto app config at PasswordPostProcessors");
                    ppr.Add(Activator.CreateInstance(type) as PasswordPostProcessor
                        ?? throw new InvalidDataException($"Invalid type {type} in crypto app config at PasswordPostProcessors: Failed to construct instance"));
                }
                options.PasswordPostProcessors = [.. ppr];
                options.UsePasswordPostProcessorsInCryptoOptions = UsePasswordPostProcessorsInCryptoOptions;
            }
            ApplyProperties(afterBootstrap: false);
            if (Algorithms is not null)
            {
                if (Algorithms.DisabledAsymmetric is string[] disabledAsymmetric)
                {
                    List<string> algos = [];
                    if (Algorithms.DefaultKeyExchangeAlgorithm is not null) algos.Add(Algorithms.DefaultKeyExchangeAlgorithm);
                    if (Algorithms.DefaultSignatureAlgorithm is not null) algos.Add(Algorithms.DefaultSignatureAlgorithm);
                    if (Algorithms.CounterKeyExchangeAlgorithm is not null) algos.Add(Algorithms.CounterKeyExchangeAlgorithm);
                    if (Algorithms.CounterSignatureAlgorithm is not null) algos.Add(Algorithms.CounterSignatureAlgorithm);
                    if (disabledAsymmetric.ContainsAny([.. algos]))
                        throw new InvalidDataException("Found default asymmetric algorithm in disabled algorithms");
                    foreach (string algo in disabledAsymmetric)
                        AsymmetricHelper.Algorithms.TryRemove(algo, out _);
                }
                if (Algorithms.DisabledEncryption is string[] disabledEncryption)
                {
                    if (Algorithms.DefaultEncryptionAlgorithm is not null && disabledEncryption.Contains(Algorithms.DefaultEncryptionAlgorithm))
                        throw new InvalidDataException("Found default encryption algorithm in disabled algorithms");
                    foreach (string algo in disabledEncryption)
                        EncryptionHelper.Algorithms.TryRemove(algo, out _);
                }
                if (Algorithms.DisabledHash is string[] disabledHash)
                {
                    List<string> algos = [];
                    if (Algorithms.DefaultHashAlgorithm is not null) algos.Add(Algorithms.DefaultHashAlgorithm);
                    if (Algorithms.PbKdf2HashAlgorithm is not null) algos.Add(Algorithms.PbKdf2HashAlgorithm);
                    if (Algorithms.Sp800_108HashAlgorithm is not null) algos.Add(Algorithms.Sp800_108HashAlgorithm);
                    if (disabledHash.ContainsAny([.. algos]))
                        throw new InvalidDataException("Found default hash algorithm in disabled algorithms");
                    foreach (string algo in disabledHash)
                        HashHelper.Algorithms.TryRemove(algo, out _);
                }
                if (Algorithms.DisabledMac is string[] disabledMac)
                {
                    List<string> algos = [];
                    if (Algorithms.DefaultMacAlgorithm is not null) algos.Add(Algorithms.DefaultMacAlgorithm);
                    if (Algorithms.CounterMacAlgorithm is not null) algos.Add(Algorithms.CounterMacAlgorithm);
                    if (disabledMac.ContainsAny([.. algos]))
                        throw new InvalidDataException("Found default MAC algorithm in disabled algorithms");
                    foreach (string algo in disabledMac)
                        MacHelper.Algorithms.TryRemove(algo, out _);
                }
                if (Algorithms.DisabledKdf is string[] disabledKdf)
                {
                    List<string> algos = [];
                    if (Algorithms.DefaultKdfAlgorithm is not null) algos.Add(Algorithms.DefaultKdfAlgorithm);
                    if (Algorithms.CounterKdfAlgorithm is not null) algos.Add(Algorithms.CounterKdfAlgorithm);
                    if (disabledKdf.ContainsAny([.. algos]))
                        throw new InvalidDataException("Found default KDF algorithm in disabled algorithms");
                    foreach (string algo in disabledKdf)
                        KdfHelper.Algorithms.TryRemove(algo, out _);
                }
            }
            ApplyProperties(afterBootstrap: true);
        }

        /// <summary>
        /// Apply
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public virtual async Task ApplyAsync(CryptoEnvironment.Options options, CancellationToken cancellationToken)
        {
            if (Algorithms is not null) await Algorithms.ApplyAsync(options, cancellationToken).DynamicContext();
            options.SkipPakeSignatureKeyValidation = SkipPakeSignatureKeyValidation;
            if (Options is not null) await Options.ApplyAsync(options, cancellationToken).DynamicContext();
            if (Rng is not null) await Rng.ApplyAsync(options, cancellationToken).DynamicContext();
            if (SecureValue is not null) await SecureValue.ApplyAsync(options, cancellationToken).DynamicContext();
            if (SignedAttributes is not null) await SignedAttributes.ApplyAsync(options, cancellationToken).DynamicContext();
            if (Limits is not null) await Limits.ApplyAsync(options, cancellationToken).DynamicContext();
            options.CryptoExceptionDelay = CryptoExceptionDelay;
            options.UseCryptoExceptionDelay = UseCryptoExceptionDelay;
            options.RemoveUnsupportedAlgorithms = RemoveUnsupportedAlgorithms;
            options.UpdateDefaultOptionsAfterRemoveUnsupportedAlgorithms = UpdateDefaultOptionsAfterRemoveUnsupportedAlgorithms;
            if (PasswordPostProcessors is not null)
            {
                List<PasswordPostProcessor> ppr = [];
                Type type;
                foreach (string typeName in PasswordPostProcessors)
                {
                    type = TypeHelper.Instance.GetType(typeName, throwOnError: true)
                        ?? throw new InvalidDataException("Invalid/unknown type name in crypto app config at PasswordPostProcessors");
                    if (!type.CanConstruct() || !typeof(PasswordPostProcessor).IsAssignableFrom(type))
                        throw new InvalidDataException($"Invalid type {type} in crypto app config at PasswordPostProcessors");
                    ppr.Add(Activator.CreateInstance(type) as PasswordPostProcessor
                        ?? throw new InvalidDataException($"Invalid type {type} in crypto app config at PasswordPostProcessors: Failed to construct instance"));
                }
                options.PasswordPostProcessors = [.. ppr];
                options.UsePasswordPostProcessorsInCryptoOptions = UsePasswordPostProcessorsInCryptoOptions;
            }
            await ApplyPropertiesAsync(afterBootstrap: false, cancellationToken).DynamicContext();
            if (Algorithms is not null)
            {
                if (Algorithms.DisabledAsymmetric is string[] disabledAsymmetric)
                {
                    List<string> algos = [];
                    if (Algorithms.DefaultKeyExchangeAlgorithm is not null) algos.Add(Algorithms.DefaultKeyExchangeAlgorithm);
                    if (Algorithms.DefaultSignatureAlgorithm is not null) algos.Add(Algorithms.DefaultSignatureAlgorithm);
                    if (Algorithms.CounterKeyExchangeAlgorithm is not null) algos.Add(Algorithms.CounterKeyExchangeAlgorithm);
                    if (Algorithms.CounterSignatureAlgorithm is not null) algos.Add(Algorithms.CounterSignatureAlgorithm);
                    if (disabledAsymmetric.ContainsAny([.. algos]))
                        throw new InvalidDataException("Found default asymmetric algorithm in disabled algorithms");
                    foreach (string algo in disabledAsymmetric)
                        AsymmetricHelper.Algorithms.TryRemove(algo, out _);
                }
                if (Algorithms.DisabledEncryption is string[] disabledEncryption)
                {
                    if (Algorithms.DefaultEncryptionAlgorithm is not null && disabledEncryption.Contains(Algorithms.DefaultEncryptionAlgorithm))
                        throw new InvalidDataException("Found default encryption algorithm in disabled algorithms");
                    foreach (string algo in disabledEncryption)
                        EncryptionHelper.Algorithms.TryRemove(algo, out _);
                }
                if (Algorithms.DisabledHash is string[] disabledHash)
                {
                    List<string> algos = [];
                    if (Algorithms.DefaultHashAlgorithm is not null) algos.Add(Algorithms.DefaultHashAlgorithm);
                    if (Algorithms.PbKdf2HashAlgorithm is not null) algos.Add(Algorithms.PbKdf2HashAlgorithm);
                    if (Algorithms.Sp800_108HashAlgorithm is not null) algos.Add(Algorithms.Sp800_108HashAlgorithm);
                    if (disabledHash.ContainsAny([.. algos]))
                        throw new InvalidDataException("Found default hash algorithm in disabled algorithms");
                    foreach (string algo in disabledHash)
                        HashHelper.Algorithms.TryRemove(algo, out _);
                }
                if (Algorithms.DisabledMac is string[] disabledMac)
                {
                    List<string> algos = [];
                    if (Algorithms.DefaultMacAlgorithm is not null) algos.Add(Algorithms.DefaultMacAlgorithm);
                    if (Algorithms.CounterMacAlgorithm is not null) algos.Add(Algorithms.CounterMacAlgorithm);
                    if (disabledMac.ContainsAny([.. algos]))
                        throw new InvalidDataException("Found default MAC algorithm in disabled algorithms");
                    foreach (string algo in disabledMac)
                        MacHelper.Algorithms.TryRemove(algo, out _);
                }
                if (Algorithms.DisabledKdf is string[] disabledKdf)
                {
                    List<string> algos = [];
                    if (Algorithms.DefaultKdfAlgorithm is not null) algos.Add(Algorithms.DefaultKdfAlgorithm);
                    if (Algorithms.CounterKdfAlgorithm is not null) algos.Add(Algorithms.CounterKdfAlgorithm);
                    if (disabledKdf.ContainsAny([.. algos]))
                        throw new InvalidDataException("Found default KDF algorithm in disabled algorithms");
                    foreach (string algo in disabledKdf)
                        KdfHelper.Algorithms.TryRemove(algo, out _);
                }
            }
            await ApplyPropertiesAsync(afterBootstrap: true, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Default algorithms
        /// </summary>
        public class DefaultAlgorithms
        {
            /// <summary>
            /// Constructor
            /// </summary>
            public DefaultAlgorithms() { }

            /// <summary>
            /// Default key exchange algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? DefaultKeyExchangeAlgorithm { get; set; }

            /// <summary>
            /// Default signature algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? DefaultSignatureAlgorithm { get; set; }

            /// <summary>
            /// Default encryption algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? DefaultEncryptionAlgorithm { get; set; }

            /// <summary>
            /// Default hash algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? DefaultHashAlgorithm { get; set; }

            /// <summary>
            /// Default KDF algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? DefaultKdfAlgorithm { get; set; }

            /// <summary>
            /// Default MAC algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? DefaultMacAlgorithm { get; set; }

            /// <summary>
            /// Counter key exchange algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? CounterKeyExchangeAlgorithm { get; set; }

            /// <summary>
            /// Counter signature algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? CounterSignatureAlgorithm { get; set; }

            /// <summary>
            /// Counter KDF algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? CounterKdfAlgorithm { get; set; }

            /// <summary>
            /// Counter MAC algorithm
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? CounterMacAlgorithm { get; set; }

            /// <summary>
            /// Default PBKDF#2 hash algorithm name for the <see cref="KdfPbKdf2Options"/>
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? PbKdf2HashAlgorithm { get; set; }

            /// <summary>
            /// Default SP800-108 hash algorithm name for the <see cref="KdfSp800_801HmacKbKdfOptions"/>
            /// </summary>
            [StringLength(byte.MaxValue)]
            public string? Sp800_108HashAlgorithm { get; set; }

            /// <summary>
            /// Disabled asymmetric algorithm names
            /// </summary>
            public string[]? DisabledAsymmetric { get; set; }

            /// <summary>
            /// Disabled encryption algorithm names
            /// </summary>
            public string[]? DisabledEncryption { get; set; }

            /// <summary>
            /// Disabled hash algorithm names
            /// </summary>
            public string[]? DisabledHash { get; set; }

            /// <summary>
            /// Disabled MAC algorithm names
            /// </summary>
            public string[]? DisabledMac { get; set; }

            /// <summary>
            /// Disabled KDF algorithm names
            /// </summary>
            public string[]? DisabledKdf { get; set; }

            /// <summary>
            /// Denied asymmetric algorithms (key is the algorithm value, value the algorithm name)
            /// </summary>
            public Dictionary<int, string>? DeniedAsymmetric { get; set; }

            /// <summary>
            /// Denied encryption algorithms (key is the algorithm value, value the algorithm name)
            /// </summary>
            public Dictionary<int, string>? DeniedEncryption { get; set; }

            /// <summary>
            /// Denied elliptic curve names
            /// </summary>
            public string[]? DeniedEllipticCurves { get; set; }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            public virtual void Apply(in CryptoEnvironment.Options options)
            {
                options.DefaultKeyExchangeAlgorithm = DefaultKeyExchangeAlgorithm;
                options.DefaultSignatureAlgorithm = DefaultSignatureAlgorithm;
                options.DefaultEncryptionAlgorithm = DefaultEncryptionAlgorithm;
                options.DefaultHashAlgorithm = DefaultHashAlgorithm;
                options.DefaultMacAlgorithm = DefaultMacAlgorithm;
                options.DefaultKdfAlgorithm = DefaultKdfAlgorithm;
                options.CounterMacAlgorithm = CounterMacAlgorithm;
                options.CounterKdfAlgorithm = CounterKdfAlgorithm;
                options.CounterKeyExchangeAlgorithm = CounterKeyExchangeAlgorithm;
                options.CounterSignatureAlgorithm = CounterSignatureAlgorithm;
                options.PbKdf2HashAlgorithm = PbKdf2HashAlgorithm;
                options.Sp800_108HashAlgorithm = Sp800_108HashAlgorithm;
                options.DeniedAsymmetric = DeniedAsymmetric;
                options.DeniedEncryption = DeniedEncryption;
                options.DeniedEllipticCurveNames = DeniedEllipticCurves;
            }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            /// <param name="cancellationToken">Cancellation token</param>
            public virtual Task ApplyAsync(CryptoEnvironment.Options options, CancellationToken cancellationToken)
            {
                options.DefaultKeyExchangeAlgorithm = DefaultKeyExchangeAlgorithm;
                options.DefaultSignatureAlgorithm = DefaultSignatureAlgorithm;
                options.DefaultEncryptionAlgorithm = DefaultEncryptionAlgorithm;
                options.DefaultHashAlgorithm = DefaultHashAlgorithm;
                options.DefaultMacAlgorithm = DefaultMacAlgorithm;
                options.DefaultKdfAlgorithm = DefaultKdfAlgorithm;
                options.CounterMacAlgorithm = CounterMacAlgorithm;
                options.CounterKdfAlgorithm = CounterKdfAlgorithm;
                options.CounterKeyExchangeAlgorithm = CounterKeyExchangeAlgorithm;
                options.CounterSignatureAlgorithm = CounterSignatureAlgorithm;
                options.PbKdf2HashAlgorithm = PbKdf2HashAlgorithm;
                options.Sp800_108HashAlgorithm = Sp800_108HashAlgorithm;
                options.DeniedAsymmetric = DeniedAsymmetric;
                options.DeniedEncryption = DeniedEncryption;
                options.DeniedEllipticCurveNames = DeniedEllipticCurves;
                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// Crypto options
        /// </summary>
        public class CryptoOptions
        {
            /// <summary>
            /// Constructor
            /// </summary>
            public CryptoOptions() { }

            /// <summary>
            /// Default maximum cipher data age for decryption
            /// </summary>
            public TimeSpan? DefaultMaximumAge { get; set; }

            /// <summary>
            /// Default maximum time offset for decryption
            /// </summary>
            public TimeSpan? DefaultMaximumTimeOffset { get; set; }

            /// <summary>
            /// Default <see cref="CryptoOptions"/> flags (will be used for requirements, too)
            /// </summary>
            public CryptoFlags? DefaultFlags { get; set; }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            public virtual void Apply(in CryptoEnvironment.Options options)
            {
                options.DefaultMaximumAge = DefaultMaximumAge;
                options.DefaultMaximumTimeOffset = DefaultMaximumTimeOffset;
                options.DefaultFlags = DefaultFlags;
            }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            /// <param name="cancellationToken">Cancellation token</param>
            public virtual Task ApplyAsync(CryptoEnvironment.Options options, CancellationToken cancellationToken)
            {
                options.DefaultMaximumAge = DefaultMaximumAge;
                options.DefaultMaximumTimeOffset = DefaultMaximumTimeOffset;
                options.DefaultFlags = DefaultFlags;
                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// RnG options
        /// </summary>
        public class RngOptions
        {
            /// <summary>
            /// Constructor
            /// </summary>
            public RngOptions() { }

            /// <summary>
            /// Use <c>/dev/random</c>, if available?
            /// </summary>
            public bool? UseDevRandom { get; set; }

            /// <summary>
            /// Require <c>/dev/random</c> (will throw, if not available)?
            /// </summary>
            public bool? RequireDevRandom { get; set; }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            public virtual void Apply(in CryptoEnvironment.Options options)
            {
                options.UseDevRandom = UseDevRandom;
                options.RequireDevRandom = RequireDevRandom;
            }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            /// <param name="cancellationToken">Cancellation token</param>
            public virtual Task ApplyAsync(CryptoEnvironment.Options options, CancellationToken cancellationToken)
            {
                options.UseDevRandom = UseDevRandom;
                options.RequireDevRandom = RequireDevRandom;
                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// Secure value options
        /// </summary>
        public class SecureValueOptions
        {
            /// <summary>
            /// Constructor
            /// </summary>
            public SecureValueOptions() { }

            /// <summary>
            /// Default encrypt timeout for <see cref="SecureValue"/>
            /// </summary>
            public TimeSpan? DefaultEncryptTimeout { get; set; }

            /// <summary>
            /// Default re-crypt timeout for <see cref="SecureValue"/>
            /// </summary>
            public TimeSpan? DefaultRecryptTimeout { get; set; }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            public virtual void Apply(in CryptoEnvironment.Options options)
            {
                options.DefaultEncryptTimeout = DefaultEncryptTimeout;
                options.DefaultRecryptTimeout = DefaultRecryptTimeout;
            }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            /// <param name="cancellationToken">Cancellation token</param>
            public virtual Task ApplyAsync(CryptoEnvironment.Options options, CancellationToken cancellationToken)
            {
                options.DefaultEncryptTimeout = DefaultEncryptTimeout;
                options.DefaultRecryptTimeout = DefaultRecryptTimeout;
                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// Signed attributes options
        /// </summary>
        public class SignedAttributesOptions
        {
            /// <summary>
            /// Constructor
            /// </summary>
            public SignedAttributesOptions() { }

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
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            public virtual void Apply(in CryptoEnvironment.Options options)
            {
                options.DefaultAllowedValidationDomains = DefaultAllowedValidationDomains;
                options.DefaultDeniedValidationDomains = DefaultDeniedValidationDomains;
                options.DefaultAllowedKeyValidationApiUris = DefaultAllowedKeyValidationApiUris;
                options.DefaultDeniedKeyValidationApiUris = DefaultDeniedKeyValidationApiUris;
                options.DefaultAllowedUsages = DefaultAllowedUsages;
                options.DefaultDeniedUsages = DefaultDeniedUsages;
                options.DefaultRequiredUsages = DefaultRequiredUsages;
                options.DefaultRequireKeyExchangeCounterKey = DefaultRequireKeyExchangeCounterKey;
                options.DefaultRequireSignatureCounterKey = DefaultRequireSignatureCounterKey;
                options.DefaultRequireCipherSuite = DefaultRequireCipherSuite;
                options.DefaultRequireSerial = DefaultRequireSerial;
            }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            /// <param name="cancellationToken">Cancellation token</param>
            public virtual Task ApplyAsync(CryptoEnvironment.Options options, CancellationToken cancellationToken)
            {
                options.DefaultAllowedValidationDomains = DefaultAllowedValidationDomains;
                options.DefaultDeniedValidationDomains = DefaultDeniedValidationDomains;
                options.DefaultAllowedKeyValidationApiUris = DefaultAllowedKeyValidationApiUris;
                options.DefaultDeniedKeyValidationApiUris = DefaultDeniedKeyValidationApiUris;
                options.DefaultAllowedUsages = DefaultAllowedUsages;
                options.DefaultDeniedUsages = DefaultDeniedUsages;
                options.DefaultRequiredUsages = DefaultRequiredUsages;
                options.DefaultRequireKeyExchangeCounterKey = DefaultRequireKeyExchangeCounterKey;
                options.DefaultRequireSignatureCounterKey = DefaultRequireSignatureCounterKey;
                options.DefaultRequireCipherSuite = DefaultRequireCipherSuite;
                options.DefaultRequireSerial = DefaultRequireSerial;
                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// Limitations
        /// </summary>
        public class Limitations
        {
            /// <summary>
            /// Constructor
            /// </summary>
            public Limitations() { }

            /// <summary>
            /// Max. array length in serialized data in bytes
            /// </summary>
            [Range(1, int.MaxValue)]
            public int? SignatureContainerMaxArrayLength { get; set; }

            /// <summary>
            /// Max. array length in serialized data in bytes
            /// </summary>
            [Range(1, int.MaxValue)]
            public int? AsymmetricKeyMaxArrayLength { get; set; }

            /// <summary>
            /// Max. key exchange data length in bytes
            /// </summary>
            [Range(1, int.MaxValue)]
            public int? MaxKeyExchangeDataLength { get; set; }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            public virtual void Apply(in CryptoEnvironment.Options options)
            {
                options.SignatureContainerMaxArrayLength = SignatureContainerMaxArrayLength;
                options.AsymmetricKeyMaxArrayLength = AsymmetricKeyMaxArrayLength;
                options.MaxKeyExchangeDataLength = MaxKeyExchangeDataLength;
            }

            /// <summary>
            /// Apply
            /// </summary>
            /// <param name="options">Options</param>
            /// <param name="cancellationToken">Cancellation token</param>
            public virtual Task ApplyAsync(CryptoEnvironment.Options options, CancellationToken cancellationToken)
            {
                options.SignatureContainerMaxArrayLength = SignatureContainerMaxArrayLength;
                options.AsymmetricKeyMaxArrayLength = AsymmetricKeyMaxArrayLength;
                options.MaxKeyExchangeDataLength = MaxKeyExchangeDataLength;
                return Task.CompletedTask;
            }
        }
    }
}
