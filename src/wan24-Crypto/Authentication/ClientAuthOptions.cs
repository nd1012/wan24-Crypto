using wan24.Core;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// Client authentication options
    /// </summary>
    public sealed record class ClientAuthOptions
    {
        /// <summary>
        /// Default options
        /// </summary>
        private static ClientAuthOptions? _DefaultOptions = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKeys">Private keys</param>
        /// <param name="login">Login ID (will be cleared!)</param>
        /// <param name="pwd">Login password (will be cleared!)</param>
        /// <param name="preSharedSecret">Pre-shared signup secret (will be cleared!)</param>
        public ClientAuthOptions(
            in PrivateKeySuite privateKeys,
            in byte[] login,
            in byte[]? pwd = null,
            in byte[]? preSharedSecret = null
            )
        {
            PrivateKeys = privateKeys;
            Login = login;
            Password = pwd;
            PreSharedSecret = preSharedSecret;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKeys">Private keys</param>
        /// <param name="preSharedSecret">Pre-shared signup secret (will be cleared!)</param>
        /// <param name="symmetricKey">Symmetric key suite (won't be disposed!)</param>
        public ClientAuthOptions(
            in PrivateKeySuite privateKeys,
            in ISymmetricKeySuite? symmetricKey,
            in byte[]? preSharedSecret = null
            )
        {
            PrivateKeys = privateKeys;
            PreSharedSecret = preSharedSecret;
            SymmetricKey = symmetricKey;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        private ClientAuthOptions() { }

        /// <summary>
        /// Default options (will be cloned for delivery)
        /// </summary>
        public static ClientAuthOptions? DefaultOptions
        {
            get => _DefaultOptions?.GetCopy();
            set => _DefaultOptions = value;
        }

        /// <summary>
        /// Public client key signing request to be processed by the server during signup (will be disposed!)
        /// </summary>
        public AsymmetricPublicKeySigningRequest? PublicKeySigningRequest { get; set; }

        /// <summary>
        /// Private keys
        /// </summary>
        public PrivateKeySuite PrivateKeys { get; private set; } = null!;

        /// <summary>
        /// Login ID (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Login { get; private set; }

        /// <summary>
        /// Login password (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Password { get; private set; }

        /// <summary>
        /// Pre-shared signup secret (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? PreSharedSecret { get; private set; }

        /// <summary>
        /// Symmetric key suite
        /// </summary>
        public ISymmetricKeySuite? SymmetricKey { get; private set; }

        /// <summary>
        /// Server public keys
        /// </summary>
        public PublicKeySuite? PublicServerKeys { get; set; }

        /// <summary>
        /// Payload (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Payload { get; set; }

        /// <summary>
        /// Payload factory
        /// </summary>
        public Pake.PayloadFactory_Delegate? PayloadFactory { get; set; }

        /// <summary>
        /// Encrypt the payload?
        /// </summary>
        public bool EncryptPayload { get; set; }

        /// <summary>
        /// Hash options (require hash algorithm)
        /// </summary>
        public CryptoOptions? HashOptions { get; set; }

        /// <summary>
        /// PAKE options (require KDF and MAC algorithms)
        /// </summary>
        public CryptoOptions? PakeOptions { get; set; }

        /// <summary>
        /// Fast PAKE authentication client (won't be disposed!)
        /// </summary>
        public FastPakeAuthClient? FastPakeAuth { get; set; }

        /// <summary>
        /// Crypto options (require encryption algorithms; shouldn't use KDF; cipher must not require MAC authentication)
        /// </summary>
        public CryptoOptions? CryptoOptions { get; set; }

        /// <summary>
        /// Server public key validation handler
        /// </summary>
        public ClientAuth.ServerPublicKeyValidation_Delegate? ServerKeyValidator { get; set; } = ClientAuth.DefaultServerPublicKeyValidator;

        /// <summary>
        /// Get the server authentication response? (the server will send an encrypted signature of the the authentication sequence excluding the client signature)
        /// </summary>
        public bool GetAuthenticationResponse { get; set; } = true;

        /// <summary>
        /// PFS keys
        /// </summary>
        internal PrivateKeySuite? PfsKeys { get; set; }

        /// <summary>
        /// Get a copy of this instance (only public properties - internal properties won't be cloned!)
        /// </summary>
        /// <returns>Instance copy</returns>
        public ClientAuthOptions GetCopy() => new()
        {
            PrivateKeys = PrivateKeys.GetCopy(),
            SymmetricKey = SymmetricKey is null
                ? null
                : new SymmetricKeySuite(SymmetricKey, (SymmetricKey as SymmetricKeySuite)?.Options.GetCopy()),
            PreSharedSecret = PreSharedSecret?.CloneArray(),
            Login = Login?.CloneArray(),
            Password = Password?.CloneArray(),
            PublicServerKeys = PublicServerKeys?.GetCopy(),
            Payload = Payload?.CloneArray(),
            PayloadFactory = PayloadFactory,
            EncryptPayload = EncryptPayload,
            HashOptions = HashOptions?.GetCopy(),
            PakeOptions = PakeOptions?.GetCopy(),
            FastPakeAuth = FastPakeAuth,
            CryptoOptions = CryptoOptions?.GetCopy(),
            ServerKeyValidator = ServerKeyValidator,
            GetAuthenticationResponse = GetAuthenticationResponse
        };
    }
}
