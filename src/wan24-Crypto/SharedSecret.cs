using wan24.Core;
using wan24.ObjectValidation;

namespace wan24.Crypto
{
    /// <summary>
    /// Shared secret (should be used as an only short living helper)
    /// </summary>
    public class SharedSecret : DisposableBase
    {
        /// <summary>
        /// Options
        /// </summary>
        protected readonly CryptoOptions Options;
        /// <summary>
        /// Token
        /// </summary>
        protected SecureByteArray Token = null!;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="token">Token (will be cleared)</param>
        /// <param name="key">Key (will be cleared)</param>
        /// <param name="options">Options with MAC algorithm (won't be cleared)</param>
        public SharedSecret(
            in byte[] token,
            in byte[] key,
            in CryptoOptions? options = null
            )
            : base(asyncDisposing: false)
        {
            Options = MacHelper.GetDefaultOptions(options);
            try
            {
                Token = new(token.Mac(key, Options));
                Secret = new(Token.Array.Mac(token, Options).Xor(Token.Array));
            }
            catch
            {
                token.Clear();
                Dispose();
                throw;
            }
            finally
            {
                key?.Clear();
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options</param>
        protected SharedSecret(in CryptoOptions? options) : base(asyncDisposing: false) => Options = MacHelper.GetDefaultOptions(options);

        /// <summary>
        /// Shared secret (used for authenticating at the remote key storage for receiving the remote secret)
        /// </summary>
        [SensitiveData, NoValidation]
        public virtual SecureByteArray Secret { get; protected set; } = null!;

        /// <summary>
        /// Protect the remote secret using a secret
        /// </summary>
        /// <param name="remoteSecret">Remote secret (size in byte must be equal to the used MAC algorithm digest size; will be overwritten!)</param>
        /// <returns>Protected remote secret (should be stored at the remote key storage and later received by authenticating with the shared secret)</returns>
        public virtual byte[] ProtectRemoteSecret(in byte[] remoteSecret)
        {
            EnsureUndisposed();
            if (remoteSecret.Length != Token.Length) throw new ArgumentOutOfRangeException(nameof(remoteSecret));
            return remoteSecret.Xor(Token.Array);
        }

        /// <summary>
        /// Derive the final secret from the received remote secret and dispose
        /// </summary>
        /// <param name="remoteSecret">Received remote secret (will be cleared!)</param>
        /// <returns>Final secret (should be cleared after use!)</returns>
        public virtual byte[] DeriveFinalSecretAndDispose(in byte[] remoteSecret)
        {
            try
            {
                EnsureUndisposed();
                return Token.Array.Mac(ProtectRemoteSecret(remoteSecret), Options);
            }
            finally
            {
                remoteSecret.Clear();
                Dispose();
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Secret?.Dispose();
            Token?.Dispose();
        }

        /// <summary>
        /// Cast as shared secret
        /// </summary>
        /// <param name="secret">Shared secret</param>
        public static implicit operator byte[](in SharedSecret secret) => secret.Secret;

        /// <summary>
        /// Derive the final secret from the received remote secret and dispose the shared secret instance
        /// </summary>
        /// <param name="secret">Shared secret (will be disposed!)</param>
        /// <param name="remoteSecret">Received remote secret (will be cleared!)</param>
        /// <returns>Final secret (should be cleared after use!)</returns>
        public static byte[] operator +(in SharedSecret secret, in byte[] remoteSecret) => secret.DeriveFinalSecretAndDispose(remoteSecret);

        /// <summary>
        /// Derive the final secret from the received remote secret and dispose the shared secret instance
        /// </summary>
        /// <param name="remoteSecret">Received remote secret (will be cleared!)</param>
        /// <param name="secret">Shared secret (will be disposed!)</param>
        /// <returns>Final secret (should be cleared after use!)</returns>
        public static byte[] operator +(in byte[] remoteSecret, in SharedSecret secret) => secret.DeriveFinalSecretAndDispose(remoteSecret);
    }
}
