using wan24.Core;

namespace wan24.Crypto
{
    // Get
    public sealed partial class KeyRing
    {
        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public byte[]? TryGetSymmetric(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return SymmetricKeys.TryGetValue(name, out byte[]? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<byte[]?> TryGetSymmetricAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return SymmetricKeys.TryGetValue(name, out byte[]? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public IAsymmetricPrivateKey? TryGetAsymmetricPrivate(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return AsymmetricPrivateKeys.TryGetValue(name, out IAsymmetricPrivateKey? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<IAsymmetricPrivateKey?> TryGetAsymmetricPrivateAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return AsymmetricPrivateKeys.TryGetValue(name, out IAsymmetricPrivateKey? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public IAsymmetricPublicKey? TryGetAsymmetricPublic(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return AsymmetricPublicKeys.TryGetValue(name, out IAsymmetricPublicKey? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<IAsymmetricPublicKey?> TryGetAsymmetricPublicAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return AsymmetricPublicKeys.TryGetValue(name, out IAsymmetricPublicKey? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public PrivateKeySuite? TryGetPrivateKey(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return PrivateKeys.TryGetValue(name, out PrivateKeySuite? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<PrivateKeySuite?> TryGetPrivateKeyAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return PrivateKeys.TryGetValue(name, out PrivateKeySuite? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public PublicKeySuite? TryGetPublicKey(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return PublicKeys.TryGetValue(name, out PublicKeySuite? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<PublicKeySuite?> TryGetPublicKeyAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return PublicKeys.TryGetValue(name, out PublicKeySuite? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public PrivateKeySuiteStore? TryGetPrivateKeySuites(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return PrivateKeySuites.TryGetValue(name, out PrivateKeySuiteStore? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<PrivateKeySuiteStore?> TryGetPrivateKeySuitesAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return PrivateKeySuites.TryGetValue(name, out PrivateKeySuiteStore? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public PublicKeySuiteStore? TryGetPublicKeySuites(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return PublicKeySuites.TryGetValue(name, out PublicKeySuiteStore? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<PublicKeySuiteStore?> TryGetPublicKeySuitesAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return PublicKeySuites.TryGetValue(name, out PublicKeySuiteStore? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public PakeRecord? TryGetPakeRecord(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return PakeRecords.TryGetValue(name, out PakeRecord? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<PakeRecord?> TryGetPakeRecordAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return PakeRecords.TryGetValue(name, out PakeRecord? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public PakeRecordStore? TryGetPakeRecordStore(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return PakeRecordStores.TryGetValue(name, out PakeRecordStore? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<PakeRecordStore?> TryGetPakeRecordStoreAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return PakeRecordStores.TryGetValue(name, out PakeRecordStore? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Key</returns>
        public SignedPkiStore? TryGetPki(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return Pkis.TryGetValue(name, out SignedPkiStore? res) ? res : null;
        }

        /// <summary>
        /// Try getting a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key</returns>
        public async Task<SignedPkiStore?> TryGetPkiAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return Pkis.TryGetValue(name, out SignedPkiStore? res) ? res : null;
        }

        /// <summary>
        /// Try getting options
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Options</returns>
        public CryptoOptions? TryGetOptions(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            return Options.TryGetValue(name, out CryptoOptions? res) ? res : null;
        }

        /// <summary>
        /// Try getting options
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Options</returns>
        public async Task<CryptoOptions?> TryGetOptionsAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            return Options.TryGetValue(name, out CryptoOptions? res) ? res : null;
        }
    }
}
