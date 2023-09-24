namespace wan24.Crypto.Networking
{
    /// <summary>
    /// Server authentication context
    /// </summary>
    public sealed class ServerAuthContext
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="serverAuth">Server authentication</param>
        /// <param name="stream">Stream</param>
        /// <param name="hashOptions">Hash options</param>
        /// <param name="pakeOptions">PAKE options</param>
        /// <param name="cryptoOptions">Options for encryption</param>
        internal ServerAuthContext(ServerAuth serverAuth, Stream stream, CryptoOptions hashOptions, CryptoOptions pakeOptions, CryptoOptions cryptoOptions)
        {
            ServerAuthentication = serverAuth;
            Stream = stream;
            HashOptions = hashOptions;
            PakeOptions = pakeOptions;
            CryptoOptions = cryptoOptions;
        }

        /// <summary>
        /// Server authentication
        /// </summary>
        public ServerAuth ServerAuthentication { get; }

        /// <summary>
        /// Stream
        /// </summary>
        public Stream Stream { get; }

        /// <summary>
        /// PAKE signup (will be disposed!)
        /// </summary>
        public PakeSignup? Signup { get; internal set; }

        /// <summary>
        /// PAKE authentication (will be disposed!)
        /// </summary>
        public PakeAuth? Authentication { get; internal set; }

        /// <summary>
        /// Client public keys (will be disposed!)
        /// </summary>
        public PublicKeySuite? PublicClientKeys { get; set; }

        /// <summary>
        /// PAKE identity (will be disposed!)
        /// </summary>
        public IPakeRecord? Identity { get; set; }

        /// <summary>
        /// Found an existing client for a signup?
        /// </summary>
        public bool FoundExistingClient { get; set; }

        /// <summary>
        /// Client PFS leys
        /// </summary>
        internal PublicKeySuite? ClientPfsKeys { get; set; }

        /// <summary>
        /// Any tagged object
        /// </summary>
        public object? Tag { get; set; }

        /// <summary>
        /// Hash options
        /// </summary>
        public CryptoOptions HashOptions { get; }

        /// <summary>
        /// PAKE options
        /// </summary>
        public CryptoOptions PakeOptions { get; }

        /// <summary>
        /// Options for encryption
        /// </summary>
        public CryptoOptions CryptoOptions { get; }

        /// <summary>
        /// Client time offset
        /// </summary>
        public TimeSpan ClientTimeOffset { get; internal set; } = TimeSpan.MinValue;

        /// <summary>
        /// Payload
        /// </summary>
        public ClientAuth.AuthPayload? Payload { get; internal set; }
    }
}
