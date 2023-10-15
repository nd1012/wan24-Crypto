using wan24.Core;

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

        /// <summary>
        /// Validate a servers public key suite using the <see cref="CryptoEnvironment.PKI"/> (can be used as <see cref="DefaultServerPublicKeyValidator"/>, for example)
        /// </summary>
        /// <param name="serverPublicKey">Servers public key suite</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the servers public key suite is trusted</returns>
        public static async Task<bool> ValidateServerPublicKeySuiteAsync(PublicKeySuite serverPublicKey, CancellationToken cancellationToken)
        {
            // PKI and signed public key required
            if (CryptoEnvironment.PKI is null) throw new InvalidOperationException("No PKI");
            if (serverPublicKey.SignedPublicKey is null) throw new InvalidDataException("Missing server signed public key");
            // Validate known and trusted root
            if (!await CryptoEnvironment.PKI.IsTrustedRootAsync(serverPublicKey.SignedPublicKey.PublicKey.ID, cancellationToken).DynamicContext())
                throw new InvalidDataException("Untrusted server public key");
            AsymmetricSignedPublicKey knownKey = await CryptoEnvironment.PKI.GetKeyAsync(serverPublicKey.SignedPublicKey.PublicKey.ID, cancellationToken).DynamicContext() ??
                throw new InvalidDataException("Loading known server public key failed");
            // Compare signed keys
            if (!serverPublicKey.SignedPublicKey.CreateSignedData().SlowCompare(knownKey.CreateSignedData())) throw new InvalidDataException("Server signed public key mismatch");
            // Validate the key suite signature
            if (serverPublicKey.Signature is null) return true;
            if (!serverPublicKey.Signature.SignerPublicKeyData.SlowCompare(serverPublicKey.SignedPublicKey.PublicKey.KeyData.Array))
                throw new InvalidDataException("Server public key suite signer mismatch");
            using MemoryPoolStream ms = new(serverPublicKey.CreateSignedData());
            await serverPublicKey.Signature.ValidateSignedDataAsync(ms, cancellationToken: cancellationToken).DynamicContext();
            return true;
        }

        /// <summary>
        /// Validate a signed servers public key suite using the <see cref="CryptoEnvironment.PKI"/> (can be used as <see cref="DefaultServerPublicKeyValidator"/>, for example)
        /// </summary>
        /// <param name="serverPublicKey">Servers public key suite</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the servers public key suite is trusted</returns>
        public static async Task<bool> ValidateSignedServerPublicKeySuiteAsync(PublicKeySuite serverPublicKey, CancellationToken cancellationToken)
        {
            // Signature, PKI and signed public key required
            if (CryptoEnvironment.PKI is null) throw new InvalidOperationException("No PKI");
            if (serverPublicKey.SignedPublicKey is null) throw new InvalidDataException("Missing server signed public key");
            if (serverPublicKey.Signature is null) throw new InvalidDataException("Unsigned public server key suite");
            // Validate known and trusted root
            if (!await CryptoEnvironment.PKI.IsTrustedRootAsync(serverPublicKey.SignedPublicKey.PublicKey.ID, cancellationToken).DynamicContext())
                throw new InvalidDataException("Untrusted server public key");
            AsymmetricSignedPublicKey knownKey = await CryptoEnvironment.PKI.GetKeyAsync(serverPublicKey.SignedPublicKey.PublicKey.ID, cancellationToken).DynamicContext() ??
                throw new InvalidDataException("Loading known server public key failed");
            // Compare signed keys
            if (!serverPublicKey.SignedPublicKey.CreateSignedData().SlowCompare(knownKey.CreateSignedData())) throw new InvalidDataException("Server signed public key mismatch");
            // Validate the key suite signature
            if (!serverPublicKey.Signature.SignerPublicKeyData.SlowCompare(serverPublicKey.SignedPublicKey.PublicKey.KeyData.Array))
                throw new InvalidDataException("Server public key suite signer mismatch");
            using MemoryPoolStream ms = new(serverPublicKey.CreateSignedData());
            await serverPublicKey.Signature.ValidateSignedDataAsync(ms, cancellationToken: cancellationToken).DynamicContext();
            return true;
        }
    }
}
