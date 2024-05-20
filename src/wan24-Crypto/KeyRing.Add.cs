using wan24.Core;

namespace wan24.Crypto
{
    // Add
    public sealed partial class KeyRing
    {
        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be cleared)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in byte[] key)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            if (key.Length > MaxSymmetricKeyLength) throw new ArgumentOutOfRangeException(nameof(key));
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.Symmetric)) return false;
            SymmetricKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be cleared)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, byte[] key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            if (key.Length > MaxSymmetricKeyLength) throw new ArgumentOutOfRangeException(nameof(key));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.Symmetric)) return false;
            SymmetricKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in IAsymmetricKey key)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            KeyTypes type = key is IAsymmetricPrivateKey
                ? KeyTypes.AsymmetricPrivate
                : KeyTypes.Public;
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, type)) return false;
            switch (key)
            {
                case IAsymmetricPrivateKey privateKey:
                    AsymmetricPrivateKeys[name] = privateKey;
                    break;
                case IAsymmetricPublicKey publicKey:
                    AsymmetricPublicKeys[name] = publicKey;
                    break;
            }
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, IAsymmetricKey key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            KeyTypes type = key is IAsymmetricPrivateKey
                ? KeyTypes.AsymmetricPrivate
                : KeyTypes.Public;
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, type)) return false;
            switch (key)
            {
                case IAsymmetricPrivateKey privateKey:
                    AsymmetricPrivateKeys[name] = privateKey;
                    break;
                case IAsymmetricPublicKey publicKey:
                    AsymmetricPublicKeys[name] = publicKey;
                    break;
            }
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in PrivateKeySuite key)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PrivateSuite)) return false;
            PrivateKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, PrivateKeySuite key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PrivateSuite)) return false;
            PrivateKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in PublicKeySuite key)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PublicSuite)) return false;
            PublicKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, PublicKeySuite key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PublicSuite)) return false;
            PublicKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in PrivateKeySuiteStore key)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PrivateSuiteStore)) return false;
            PrivateKeySuites[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, PrivateKeySuiteStore key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PrivateSuiteStore)) return false;
            PrivateKeySuites[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in PublicKeySuiteStore key)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PublicSuiteStore)) return false;
            PublicKeySuites[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, PublicKeySuiteStore key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PublicSuiteStore)) return false;
            PublicKeySuites[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in PakeRecord key)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.Pake)) return false;
            PakeRecords[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, PakeRecord key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.Pake)) return false;
            PakeRecords[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in PakeRecordStore key)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PakeStore)) return false;
            PakeRecordStores[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, PakeRecordStore key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.PakeStore)) return false;
            PakeRecordStores[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in SignedPkiStore key)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.Pki)) return false;
            Pkis[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, SignedPkiStore key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.Pki)) return false;
            Pkis[name] = key;
            return true;
        }

        /// <summary>
        /// Try adding crypto options
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="options">Options (won't be cleared)</param>
        /// <returns>If added</returns>
        public bool TryAdd(in string name, in CryptoOptions options)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = Sync;
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.Options)) return false;
            Options[name] = options;
            return true;
        }

        /// <summary>
        /// Try adding crypto options
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="options">Options (won't be cleared)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If added</returns>
        public async Task<bool> TryAddAsync(string name, CryptoOptions options, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (name.Length > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(name));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (KeyNames.Count > MaxCount) throw new OutOfMemoryException();
            if (!KeyNames.TryAdd(name, KeyTypes.Options)) return false;
            Options[name] = options;
            return true;
        }
    }
}
