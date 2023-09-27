using wan24.Core;

namespace wan24.Crypto.Networking
{
    /// <summary>
    /// Client authentication options
    /// </summary>
    public sealed class ClientAuthOptions
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKeys">Private keys</param>
        /// <param name="login">Login ID (will be cleared!)</param>
        /// <param name="pwd">Login password (will be cleared!)</param>
        /// <param name="preSharedSecret">Pre-shared signup secret (will be cleared!)</param>
        public ClientAuthOptions(in PrivateKeySuite privateKeys, in byte[] login, in byte[]? pwd = null, in byte[]? preSharedSecret = null)
        {
            PrivateKeys = privateKeys;
            Login = login;
            Password = pwd;
            PreSharedSecret = preSharedSecret;
        }

        /// <summary>
        /// Public client key signing request to be processed by the server during signup (will be disposed!)
        /// </summary>
        public AsymmetricPublicKeySigningRequest? PublicKeySigningRequest { get; set; }

        /// <summary>
        /// Private keys
        /// </summary>
        public PrivateKeySuite PrivateKeys { get; }

        /// <summary>
        /// Login ID (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[] Login { get; }

        /// <summary>
        /// Login password (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Password { get; }

        /// <summary>
        /// Pre-shared signup secret
        /// </summary>
        [SensitiveData]
        public byte[]? PreSharedSecret { get; }

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
        [SensitiveData]
        internal PrivateKeySuite? PfsKeys { get; set; }
    }
}
