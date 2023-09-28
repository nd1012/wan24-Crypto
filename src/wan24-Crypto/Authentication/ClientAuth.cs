namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// Client authentication sequence helper
    /// </summary>
    public static partial class ClientAuth
    {
        /// <summary>
        /// Protocol version
        /// </summary>
        public const byte VERSION = 1;
        /// <summary>
        /// Purpose of the signature from the signup
        /// </summary>
        public const string SIGNUP_SIGNATURE_PURPOSE = "Signup";
        /// <summary>
        /// Purpose of the signature from the authentication
        /// </summary>
        public const string AUTH_SIGNATURE_PURPOSE = "Authentication";

        /// <summary>
        /// Default public server key validator
        /// </summary>
        public static ServerPublicKeyValidation_Delegate? DefaultServerPublicKeyValidator { get; set; }

        /// <summary>
        /// Delegate for a public server key validation handler
        /// </summary>
        /// <param name="serverPublicKey">Server public key (will be disposed!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If to use the key (may throw also)</returns>
        public delegate Task<bool> ServerPublicKeyValidation_Delegate(PublicKeySuite serverPublicKey, CancellationToken cancellationToken);
    }
}
