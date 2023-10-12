namespace wan24.Crypto
{
    /// <summary>
    /// Signed attribute name examples/suggestions for an <see cref="AsymmetricSignedPublicKey"/> / <see cref="AsymmetricPublicKeySigningRequest"/>
    /// </summary>
    public static class SignedAttributes
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
        /// Should contain a https URI which targets a RESTful API for key validation (should receive the (possibly base64 encoded) key ID as path component and answer, if 
        /// the key was revoked)
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
    }
}
