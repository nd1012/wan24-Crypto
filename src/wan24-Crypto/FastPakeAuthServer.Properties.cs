using wan24.Core;
using static wan24.Core.TranslationHelper;

namespace wan24.Crypto
{
    // Properties
    public sealed partial class FastPakeAuthServer
    {
        /// <summary>
        /// External thread synchronization
        /// </summary>
        public SemaphoreSync Sync { get; } = new();

        /// <summary>
        /// Use the external thread synchronization during the <c>HandleAuth*</c> methods to synchronize any identity access?
        /// </summary>
        public bool UseSync { get; set; }

        /// <summary>
        /// GUID
        /// </summary>
        public string GUID { get; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Name
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// PAKE instance
        /// </summary>
        public Pake Pake { get; } = null!;

        /// <summary>
        /// Key
        /// </summary>
        public SecureValue Key { get; } = null!;

        /// <summary>
        /// Secret
        /// </summary>
        public SecureValue Secret { get; } = null!;

        /// <summary>
        /// Signature key
        /// </summary>
        public SecureValue SignatureKey { get; } = null!;

        /// <summary>
        /// Authentication count (including errors)
        /// </summary>
        public int AuthCount => _AuthCount;

        /// <summary>
        /// Authentication error count
        /// </summary>
        public int AuthErrorCount => _AuthErrorCount;

        /// <inheritdoc/>
        public IEnumerable<Status> State
        {
            get
            {
                yield return new(__("GUID"), GUID, __("Unique ID of the fast PAKE server"));
                yield return new(__("Name"), Name, __("Name of the fast PAKE server"));
                yield return new(__("Identifier"), Convert.ToHexString(Pake.Identifier), __("Peer identifier"));
                yield return new(__("Count"), _AuthCount, __("Authentication count since initialization"));
                yield return new(__("Errors"), _AuthErrorCount, __("Authentication error count since initialization"));
            }
        }
    }
}
