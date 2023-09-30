namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE server authentication options
    /// </summary>
    public sealed class PakeServerAuthOptions
    {
        /// <summary>
        /// Cnstructor
        /// </summary>
        public PakeServerAuthOptions() { }

        /// <summary>
        /// Signup validator
        /// </summary>
        public PakeServerAuth.SignupValidator_Delegate? SignupValidator { get; set; }

        /// <summary>
        /// Signup handler
        /// </summary>
        public PakeServerAuth.Signup_Delegate? SignupHandler { get; set; }

        /// <summary>
        /// Authentication handler
        /// </summary>
        public PakeServerAuth.Authentication_Delegate? AuthenticationHandler { get; set; }

        /// <summary>
        /// Client authentication information factory
        /// </summary>
        public PakeServerAuth.ClientAuthFactory_Delegate? ClientAuthFactory { get; set; }

        /// <summary>
        /// PAKE options (require KDF and MAC algorithms; will be cleared!)
        /// </summary>
        public CryptoOptions? PakeOptions { get; set; }

        /// <summary>
        /// Decrypt the payload?
        /// </summary>
        public bool DecryptPayload { get; set; }

        /// <summary>
        /// Skip the PAKE signature key validation (KDF) during authentication?
        /// </summary>
        public bool SkipSignatureKeyValidation { get; set; }

        /// <summary>
        /// Crypto options (require encryption algorithms; shouldn't use KDF; cipher must not require MAC authentication; will be cleared!)
        /// </summary>
        public CryptoOptions? CryptoOptions { get; set; }

        /// <summary>
        /// Session key value encrypt timeout (<see cref="SecureValue"/>)
        /// </summary>
        public TimeSpan? EncryptTimeout { get; set; }

        /// <summary>
        /// Session key value re-crypt timeout (<see cref="SecureValue"/>)
        /// </summary>
        public TimeSpan? RecryptTimeout { get; set; }

        /// <summary>
        /// Options for encrypting the session key value (<see cref="SecureValue"/>)
        /// </summary>
        public CryptoOptions? SessionKeyCryptoOptions { get; set; }

        /// <summary>
        /// Session key KEK length in bytes (<see cref="SecureValue"/>)
        /// </summary>
        public int SessionKeyKekLength { get; set; } = 64;

        /// <summary>
        /// Send a response on authentication?
        /// </summary>
        public bool SendAuthenticationResponse { get; set; } = true;

        /// <summary>
        /// PAKE authentication record pool
        /// </summary>
        public IPakeAuthRecordPool? AuthRecordPool { get; set; }

        /// <summary>
        /// Max. time difference to a peers time
        /// </summary>
        public TimeSpan MaxTimeDifference { get; set; } = TimeSpan.FromMinutes(5);
    }
}
