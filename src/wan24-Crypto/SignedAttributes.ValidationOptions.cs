using System.Collections.ObjectModel;

namespace wan24.Crypto
{
    // Validation options
    public static partial class SignedAttributes
    {
        /// <summary>
        /// Validation options
        /// </summary>
        public record class ValidationOptions : ICloneable
        {
            /// <summary>
            /// Constructor
            /// </summary>
            public ValidationOptions() { }

            /// <summary>
            /// Default allowed validation domains
            /// </summary>
            public static ReadOnlyCollection<string>? DefaultAllowedValidationDomains { get; set; }

            /// <summary>
            /// Default denied validation domains
            /// </summary>
            public static ReadOnlyCollection<string>? DefaultDeniedValidationDomains { get; set; }

            /// <summary>
            /// Default allowed key validation API URIs
            /// </summary>
            public static ReadOnlyCollection<string>? DefaultAllowedKeyValidationApiUris { get; set; }

            /// <summary>
            /// Default denied key validation API URIs
            /// </summary>
            public static ReadOnlyCollection<string>? DefaultDeniedKeyValidationApiUris { get; set; }

            /// <summary>
            /// Default allowed key usages
            /// </summary>
            public static AsymmetricAlgorithmUsages? DefaultAllowedUsages { get; set; }

            /// <summary>
            /// Default denied key usages
            /// </summary>
            public static AsymmetricAlgorithmUsages? DefaultDeniedUsages { get; set; }

            /// <summary>
            /// Default required key usages
            /// </summary>
            public static AsymmetricAlgorithmUsages? DefaultRequiredUsages { get; set; }

            /// <summary>
            /// Default require a key exchange counter key?
            /// </summary>
            public static bool DefaultRequireKeyExchangeCounterKey { get; set; }

            /// <summary>
            /// Default require a signature counter key?
            /// </summary>
            public static bool DefaultRequireSignatureCounterKey { get; set; }

            /// <summary>
            /// Default require a cipher suite (<see cref="CryptoOptions"/>)?
            /// </summary>
            public static bool DefaultRequireCipherSuite { get; set; }

            /// <summary>
            /// Default require a public key revision serial number?
            /// </summary>
            public static bool DefaultRequireSerial { get; set; }

            /// <summary>
            /// Allowed validation domains
            /// </summary>
            public ReadOnlyCollection<string>? AllowedValidationDomains { get; set; } = DefaultAllowedValidationDomains;

            /// <summary>
            /// Denied validation domains
            /// </summary>
            public ReadOnlyCollection<string>? DeniedValidationDomains { get; set; } = DefaultDeniedValidationDomains;

            /// <summary>
            /// Allowed key validation API URIs
            /// </summary>
            public ReadOnlyCollection<string>? AllowedKeyValidationApiUris { get; set; } = DefaultAllowedKeyValidationApiUris;

            /// <summary>
            /// Denied key validation API URIs
            /// </summary>
            public ReadOnlyCollection<string>? DeniedKeyValidationApiUris { get; set; } = DefaultDeniedKeyValidationApiUris;

            /// <summary>
            /// Perform an online key validation (asynchronous only)?
            /// </summary>
            public bool OnlineKeyValidation { get; set; }

            /// <summary>
            /// Allowed key usages
            /// </summary>
            public AsymmetricAlgorithmUsages? AllowedUsages { get; set; } = DefaultAllowedUsages;

            /// <summary>
            /// Denied key usages
            /// </summary>
            public AsymmetricAlgorithmUsages? DeniedUsages { get; set; } = DefaultDeniedUsages;

            /// <summary>
            /// Required key usages
            /// </summary>
            public AsymmetricAlgorithmUsages? RequiredUsages { get; set; } = DefaultRequiredUsages;

            /// <summary>
            /// Require a key exchange counter key?
            /// </summary>
            public bool RequireKeyExchangeCounterKey { get; set; } = DefaultRequireKeyExchangeCounterKey;

            /// <summary>
            /// Require a signature counter key?
            /// </summary>
            public bool RequireSignatureCounterKey { get; set; } = DefaultRequireSignatureCounterKey;

            /// <summary>
            /// Require a cipher suite (<see cref="CryptoOptions"/>)?
            /// </summary>
            public bool RequireCipherSuite { get; set; } = DefaultRequireCipherSuite;

            /// <summary>
            /// Require a public key revision serial number?
            /// </summary>
            public bool RequireSerial { get; set; } = DefaultRequireSerial;

            /// <summary>
            /// Require a PKI signature permission?
            /// </summary>
            public bool RequirePkiSignaturePermission { get; set; }

            /// <summary>
            /// PKI to use for key exchange/signature key identfier validation
            /// </summary>
            public SignedPkiStore? PKI { get; set; } = CryptoEnvironment.PKI;

            /// <summary>
            /// Get a copy of this instance
            /// </summary>
            /// <returns>Instance copy</returns>
            public virtual ValidationOptions GetCopy() => new()
            {
                AllowedValidationDomains = AllowedValidationDomains,
                DeniedValidationDomains = DeniedValidationDomains,
                AllowedKeyValidationApiUris = AllowedKeyValidationApiUris,
                DeniedKeyValidationApiUris = DeniedKeyValidationApiUris,
                OnlineKeyValidation = OnlineKeyValidation,
                AllowedUsages = AllowedUsages,
                DeniedUsages = DeniedUsages,
                RequiredUsages = RequiredUsages,
                RequireKeyExchangeCounterKey = RequireKeyExchangeCounterKey,
                RequireSignatureCounterKey = RequireSignatureCounterKey,
                RequireCipherSuite = RequireCipherSuite,
                RequireSerial = RequireSerial,
                RequirePkiSignaturePermission = RequirePkiSignaturePermission
            };

            /// <inheritdoc/>
            object ICloneable.Clone() => GetCopy();
        }
    }
}
