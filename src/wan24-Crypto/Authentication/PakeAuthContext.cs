using wan24.Core;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE authentication context
    /// </summary>
    public sealed class PakeAuthContext : DisposableBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="identity">Peer identity (will be cleared/disposed!)</param>
        /// <param name="sessionKey">Session key (will be cleared!)</param>
        /// <param name="payload">Payload (will be cleared!)</param>
        /// <param name="identifier">Random identifier (for signup only; will be cleared!)</param>
        /// <param name="key">Random key (for signup only; will be cleared!)</param>
        /// <param name="secret">PAKE secret (for signup only; will be cleared!)</param>
        /// <param name="authKey">PAKE authentication key (for signup only; will be cleared!)</param>
        /// <param name="signatureKey">PAKE signature key (for signup only; will be cleared!)</param>
        internal PakeAuthContext(
            in IPakeRecord identity,
            in byte[] sessionKey,
            in byte[] payload,
            in byte[]? identifier = null,
            in byte[]? key = null,
            in byte[]? secret = null,
            in byte[]? authKey = null,
            in byte[]? signatureKey = null
            )
            : base()
        {
            try
            {
                Identity = identity;
                SessionKey = sessionKey;
                Payload = payload;
                if (identifier is null) return;
                if (key is null) throw new ArgumentNullException(nameof(key), "Required for server side signup context");
                if (secret is null) throw new ArgumentNullException(nameof(secret), "Required for server side signup context");
                if (authKey is null) throw new ArgumentNullException(nameof(authKey), "Required for server side signup context");
                if (signatureKey is null) throw new ArgumentNullException(nameof(signatureKey), "Required for server side signup context");
                Identifier = identifier;
                Key = key;
                Secret = secret;
                AuthKey = authKey;
                SignatureKey = signatureKey;
            }
            catch
            {
                Dispose();
                identifier?.Clear();
                key?.Clear();
                secret?.Clear();
                authKey?.Clear();
                throw;
            }
        }

        /// <summary>
        /// Peer identity (will be cleared/disposed!)
        /// </summary>
        public IPakeRecord Identity { get; }

        /// <summary>
        /// Session key (will be disposed!)
        /// </summary>
        public SecureValue SessionKey { get; }

        /// <summary>
        /// Payload (will be cleared!)
        /// </summary>
        byte[] Payload { get; }

        /// <summary>
        /// Random identifier (for signup only; will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Identifier { get; }

        /// <summary>
        /// Random key (for signup only; will be cleared!)
        /// </summary>
        [SensitiveData]
        public SecureValue? Key { get; }

        /// <summary>
        /// PAKE secret (for signup only; will be cleared!)
        /// </summary>
        [SensitiveData]
        public SecureValue? Secret { get; }

        /// <summary>
        /// PAKE authentication key (for signup only; will be cleared!)
        /// </summary>
        [SensitiveData]
        public SecureValue? AuthKey { get; }

        /// <summary>
        /// PAKE signature key (for signup only; will be cleared!)
        /// </summary>
        [SensitiveData]
        public SecureValue? SignatureKey { get; }

        /// <summary>
        /// Clear the PAKE signup data of the peer (identifier, key, secret and authentication key)
        /// </summary>
        public void ClearSignupData()
        {
            EnsureUndisposed(allowDisposing: true);
            Identifier?.Clear();
            Key?.Dispose();
            Secret?.Dispose();
            AuthKey?.Dispose();
            SignatureKey?.Dispose();
        }

        /// <summary>
        /// Clear the PAKE signup data of the peer (identifier, key, secret and authentication key)
        /// </summary>
        public async Task ClearRandomPakeDataAsync()
        {
            EnsureUndisposed(allowDisposing: true);
            Identifier?.Clear();
            if (Key is not null) await Key.DisposeAsync().DynamicContext();
            if (Secret is not null) await Secret.DisposeAsync().DynamicContext();
            if (AuthKey is not null) await AuthKey.DisposeAsync().DynamicContext();
            if (SignatureKey is not null) await SignatureKey.DisposeAsync().DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            ClearSignupData();
            SessionKey.Dispose();
            Identity.Dispose();
            Payload.Clear();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await ClearRandomPakeDataAsync().DynamicContext();
            await SessionKey.DisposeAsync().DynamicContext();
            await Identity.DisposeAsync().DynamicContext();
            Payload.Clear();
        }
    }
}
