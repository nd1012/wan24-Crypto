using wan24.Core;

namespace wan24.Crypto
{
    // Remove
    public sealed partial class KeyRing
    {
        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed key (don't forget to clear)</returns>
        public byte[]? TryRemoveSymmetric(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!SymmetricKeys.TryRemove(name, out byte[]? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed key (don't forget to clear)</returns>
        public async Task<byte[]?> TryRemoveSymmetricAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!SymmetricKeys.TryRemove(name, out byte[]? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public IAsymmetricKey? TryRemoveAsymmetric(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            IAsymmetricKey? res = null;
            if (AsymmetricPrivateKeys.TryRemove(name, out IAsymmetricPrivateKey? privateKey))
            {
                res = privateKey;
            }
            else if (AsymmetricPublicKeys.TryRemove(name, out IAsymmetricPublicKey? publicKey))
            {
                res = publicKey;
            }
            else
            {
                return null;
            }
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public async Task<IAsymmetricKey?> TryRemoveAsymmetricAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            IAsymmetricKey? res = null;
            if (AsymmetricPrivateKeys.TryRemove(name, out IAsymmetricPrivateKey? privateKey))
            {
                res = privateKey;
            }
            else if (AsymmetricPublicKeys.TryRemove(name, out IAsymmetricPublicKey? publicKey))
            {
                res = publicKey;
            }
            else
            {
                return null;
            }
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public PrivateKeySuite? TryRemovePrivateKeySuite(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PrivateKeys.TryRemove(name, out PrivateKeySuite? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public async Task<PrivateKeySuite?> TryRemovePrivateKeySuiteAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PrivateKeys.TryRemove(name, out PrivateKeySuite? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public PublicKeySuite? TryRemovePublicKeySuite(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PublicKeys.TryRemove(name, out PublicKeySuite? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public async Task<PublicKeySuite?> TryRemovePublicKeySuiteAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PublicKeys.TryRemove(name, out PublicKeySuite? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public PrivateKeySuiteStore? TryRemovePrivateKeySuiteStore(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PrivateKeySuites.TryRemove(name, out PrivateKeySuiteStore? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public async Task<PrivateKeySuiteStore?> TryRemovePrivateKeySuiteStoreAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PrivateKeySuites.TryRemove(name, out PrivateKeySuiteStore? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public PublicKeySuiteStore? TryRemovePublicKeySuiteStore(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PublicKeySuites.TryRemove(name, out PublicKeySuiteStore? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public async Task<PublicKeySuiteStore?> TryRemovePublicKeySuiteStoreAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PublicKeySuites.TryRemove(name, out PublicKeySuiteStore? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public PakeRecord? TryRemovePakeRecord(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PakeRecords.TryRemove(name, out PakeRecord? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public async Task<PakeRecord?> TryRemovePakeRecordAsnyc(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PakeRecords.TryRemove(name, out PakeRecord? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public PakeRecordStore? TryRemovePakeRecordStore(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PakeRecordStores.TryRemove(name, out PakeRecordStore? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public async Task<PakeRecordStore?> TryRemovePakeRecordStoreAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PakeRecordStores.TryRemove(name, out PakeRecordStore? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public SignedPkiStore? TryRemovePki(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!Pkis.TryRemove(name, out SignedPkiStore? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed key (don't forget to dispose)</returns>
        public async Task<SignedPkiStore?> TryRemovePkiAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!Pkis.TryRemove(name, out SignedPkiStore? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing opions
        /// </summary>
        /// <param name="name">Name</param>
        /// <returns>Removed options</returns>
        public CryptoOptions? TryRemoveOptions(in string name)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!Options.TryRemove(name, out CryptoOptions? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }

        /// <summary>
        /// Try removing opions
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Removed options</returns>
        public async Task<CryptoOptions?> TryRemoveOptionsAsync(string name, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!Options.TryRemove(name, out CryptoOptions? res)) return null;
            KeyNames.TryRemove(name, out _);
            return res;
        }
    }
}
