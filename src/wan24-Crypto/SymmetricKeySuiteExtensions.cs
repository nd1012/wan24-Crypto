using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <see cref="ISymmetricKeySuite"/> extensions
    /// </summary>
    public static class SymmetricKeySuiteExtensions
    {
        /// <summary>
        /// Derive a session key
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        /// <param name="payload">Payload (will be cleared!)</param>
        /// <param name="options">Options</param>
        /// <param name="cryptoOptions">Options for encryption</param>
        /// <param name="encryptPayload">Encrypt the payload?</param>
        /// <returns>Session key and the authentication request to be sent to the server (don't forget to dispose!)</returns>
        public static (byte[] SessionKey, PakeAuth AuthenticationRequest) DeriveSessionKey(
            this ISymmetricKeySuite key,
            in byte[]? payload = null,
            in CryptoOptions? options = null,
            in CryptoOptions? cryptoOptions = null,
            in bool encryptPayload = false
            )
        {
            using Pake pake = new(key, options?.GetCopy(), cryptoOptions?.GetCopy());
            PakeAuth auth = pake.CreateAuth(payload, encryptPayload);
            return (pake.SessionKey.CloneArray(), auth);
        }

        /// <summary>
        /// Create a signup and derive a session key
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        /// <param name="payload">Payload (will be cleared!)</param>
        /// <param name="options">Options</param>
        /// <returns>Session key and the signup request to be sent to the server (don't forget to dispose!)</returns>
        public static (byte[] SessionKey, PakeSignup SignupRequest) CreateSignup(
            this ISymmetricKeySuite key,
            in byte[]? payload = null,
            in CryptoOptions? options = null
            )
        {
            using Pake pake = new(key, options?.GetCopy());
            PakeSignup signup = pake.CreateSignup(payload);
            return (pake.SessionKey.CloneArray(), signup);
        }
    }
}
