using wan24.Core;
using wan24.ObjectValidation;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// Client authentication context
    /// </summary>
    public sealed class ClientAuthContext : DisposableBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="context">Context</param>
        internal ClientAuthContext(in ServerAuthOptions options, in ServerAuthContext context)
            : base(asyncDisposing: false)
        {
            IsNewClient = !context.FoundExistingClient && context.Payload!.IsNewClient;
            IsTemporaryClient = !context.FoundExistingClient && context.Payload!.IsTemporaryClient;
            try
            {
                PublicKeys = context.PublicClientKeys ?? throw new ArgumentException("Missing public client keys", nameof(context));
                Identity = new(context.Identity ?? throw new ArgumentException("Missing identity", nameof(context)));
                SessionKey = new(
                    context.CryptoOptions.Password?.CloneArray() ?? throw new ArgumentException("Missing session key", nameof(context)),
                    options.EncryptTimeout,
                    options.RecryptTimeout,
                    options.SessionKeyCryptoOptions,
                    options.SessionKeyKekLength
                    );
                Payload = context.Payload?.Payload is null ? null : new(context.Payload.Payload);
                TimeOffset = context.ClientTimeOffset;
                Tag = context.Tag;
           }
            catch
            {
                Dispose();
                throw;
            }
        }

        /// <summary>
        /// Created time
        /// </summary>
        public DateTime Created { get; } = DateTime.Now;

        /// <summary>
        /// Is a new client?
        /// </summary>
        public bool IsNewClient { get; }

        /// <summary>
        /// Is a temporary client?
        /// </summary>
        public bool IsTemporaryClient { get; }

        /// <summary>
        /// Public keys (will be disposed!)
        /// </summary>
        public PublicKeySuite PublicKeys { get; }

        /// <summary>
        /// Identity (will be cleared!)
        /// </summary>
        [SensitiveData]
        public PakeRecord Identity { get; }

        /// <summary>
        /// Session key (will be disposed!)
        /// </summary>
        [NoValidation, SensitiveData]
        public SecureValue SessionKey { get; }

        /// <summary>
        /// Payload (will be disposed!)
        /// </summary>
        [NoValidation, SensitiveData]
        public SecureByteArray? Payload { get; }

        /// <summary>
        /// Client time offset
        /// </summary>
        public TimeSpan TimeOffset { get; }

        /// <summary>
        /// Any tagged object
        /// </summary>
        public object? Tag { get; set; }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            SessionKey?.Dispose();
            Identity?.Clear();
            PublicKeys?.Dispose();
            Payload?.Dispose();
        }
    }
}
