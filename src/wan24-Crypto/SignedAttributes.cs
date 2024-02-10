namespace wan24.Crypto
{
    /// <summary>
    /// Signed attribute name examples/suggestions for an <see cref="AsymmetricSignedPublicKey"/> / <see cref="AsymmetricPublicKeySigningRequest"/> and validation helper
    /// </summary>
    public static partial class SignedAttributes
    {
        /// <summary>
        /// Should contain the domain name of the PKI (yourcompany.com, for example)
        /// </summary>
        public const string PKI_DOMAIN = "Domain";
        /// <summary>
        /// Should contain an owner identifier, which can be used to query owner meta data from a store (binary values may be base64 encoded and encrypted, for example)
        /// </summary>
        public const string OWNER_IDENTIFIER = "OwnerId";
        /// <summary>
        /// Should contain a public https URI which targets a RESTful API for key validation (should receive the (possibly base64 encoded) key ID as path component and answer, if 
        /// the key was revoked by returning the revokation timestamp (UTC <see cref="DateTime"/> ticks) or zero, if it wasn't revoked)
        /// </summary>
        public const string ONLINE_KEY_VALIDATION_API_URI = "KeyValidationUri";
        /// <summary>
        /// Should contain the numeric value of the granted <see cref="AsymmetricAlgorithmUsages"/> flags for the signed key (an asymmetric algorithm may be able to exchange 
        /// a key AND sign)
        /// </summary>
        public const string GRANTED_KEY_USAGES = "GrantedKeyUsages";
        /// <summary>
        /// Should contain the (base64 encoded?) public key identifier of the key which is granted for key exchange with this signed key owner
        /// </summary>
        public const string KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER = "KePublicKey";
        /// <summary>
        /// Should contain the (base64 encoded?) public counter key identifier of the key which is granted for key exchange with this signed key owner
        /// </summary>
        public const string KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER = "KePublicCounterKey";
        /// <summary>
        /// Should contain the (base64 encoded?) public key identifier of the key which is granted for signatures from this signed key owner
        /// </summary>
        public const string SIGNATURE_PUBLIC_KEY_IDENTIFIER = "SigPublicKey";
        /// <summary>
        /// Should contain the (base64 encoded?) public counter key identifier of the key which is granted for signatures from this signed key owner
        /// </summary>
        public const string SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER = "SigPublicCounterKey";
        /// <summary>
        /// Should contain the (base64 encoded?) granted/confirmed cipher suite (<see cref="CryptoOptions"/>) of this signed key owner
        /// </summary>
        public const string CIPHER_SUITE = "CipherSuite";
        /// <summary>
        /// Should contain the numeric key revision of the owner (not an overall PKI key counter)
        /// </summary>
        public const string SERIAL = "Serial";
        /// <summary>
        /// Permitted to sign sub-keys?
        /// </summary>
        public const string PKI_SIGNATURE = "PkiSig";

        /// <summary>
        /// Additional attribute validation
        /// </summary>
        public static Validate_Delegate? AdditionalValidation { get; set; }

        /// <summary>
        /// Additional attribute validation
        /// </summary>
        public static ValidateAsync_Delegate? AdditionalValidationAsync { get; set; }

        /// <summary>
        /// Delegate for an additional attribute validator
        /// </summary>
        /// <param name="id">Key ID</param>
        /// <param name="attributes">Attributes</param>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <param name="options">Options</param>
        /// <param name="keyStore">Key owner public key store</param>
        /// <returns>If the attributes are valid</returns>
        public delegate bool Validate_Delegate(
            byte[] id,
            IReadOnlyDictionary<string, string> attributes,
            bool throwOnError,
            ValidationOptions? options,
            PublicKeySuiteStore? keyStore
            );

        /// <summary>
        /// Delegate for an additional attribute validator
        /// </summary>
        /// <param name="id">Key ID</param>
        /// <param name="attributes">Attributes</param>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <param name="options">Options</param>
        /// <param name="keyStore">Key owner public key store</param>
        /// <param name="usage">Key usage time</param>
        /// <param name="services">Service provider to use, if <c>httpClient</c> wasn't given for online key validation</param>
        /// <param name="httpClient">http client to use for online key validation (won't be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the attributes are valid</returns>
        public delegate Task<bool> ValidateAsync_Delegate(
            byte[] id,
            IReadOnlyDictionary<string, string> attributes,
            bool throwOnError,
            ValidationOptions? options,
            PublicKeySuiteStore? keyStore,
            DateTime? usage,
            IServiceProvider? services,
            HttpClient? httpClient,
            CancellationToken cancellationToken
            );
    }
}
