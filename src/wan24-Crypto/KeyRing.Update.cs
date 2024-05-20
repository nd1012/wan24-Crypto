using System.Diagnostics.CodeAnalysis;
using wan24.Core;

namespace wan24.Crypto
{
    // Update
    public sealed partial class KeyRing
    {
        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be cleared)</param>
        /// <param name="existing">Existing key (don't forget to clear)</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in byte[] key, [NotNullWhen(returnValue: true)] out byte[]? existing)
        {
            EnsureUndisposed();
            if (key.Length > MaxSymmetricKeyLength) throw new ArgumentOutOfRangeException(nameof(key));
            using SemaphoreSyncContext ssc = Sync;
            if (!SymmetricKeys.TryGetValue(name, out existing)) return false;
            SymmetricKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be cleared)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result (don't forget to clear)</returns>
        public async Task<TryAsyncResult<byte[]>> TryUpdateAsync(string name, byte[] key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (key.Length > MaxSymmetricKeyLength) throw new ArgumentOutOfRangeException(nameof(key));
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!SymmetricKeys.TryGetValue(name, out byte[]? existing)) return false;
            SymmetricKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="existing">Existing key (don't forget to dispose)</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in IAsymmetricKey key, [NotNullWhen(returnValue: true)] out IAsymmetricKey? existing)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            switch (key)
            {
                case IAsymmetricPrivateKey privateKey:
                    {
                        if (!AsymmetricPrivateKeys.TryGetValue(name, out IAsymmetricPrivateKey? existingKey))
                        {
                            existing = null;
                            return false;
                        }
                        existing = existingKey;
                        AsymmetricPrivateKeys[name] = privateKey;
                    }
                    break;
                case IAsymmetricPublicKey publicKey:
                    {
                        if (!AsymmetricPublicKeys.TryGetValue(name, out IAsymmetricPublicKey? existingKey))
                        {
                            existing = null;
                            return false;
                        }
                        existing = existingKey;
                        AsymmetricPublicKeys[name] = publicKey;
                    }
                    break;
                default:
                    throw new InvalidProgramException();
            }
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If updated (don't forget to dispose)</returns>
        public async Task<TryAsyncResult<IAsymmetricKey>> TryUpdateAsync(string name, IAsymmetricKey key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            switch (key)
            {
                case IAsymmetricPrivateKey privateKey:
                    {
                        if (!AsymmetricPrivateKeys.TryGetValue(name, out IAsymmetricPrivateKey? existingKey)) return false;
                        IAsymmetricKey existing = existingKey;
                        AsymmetricPrivateKeys[name] = privateKey;
                        return new(existing);
                    }
                case IAsymmetricPublicKey publicKey:
                    {
                        if (!AsymmetricPublicKeys.TryGetValue(name, out IAsymmetricPublicKey? existingKey)) return false;
                        IAsymmetricKey existing = existingKey;
                        AsymmetricPublicKeys[name] = publicKey;
                        return new(existing);
                    }
                default:
                    throw new InvalidProgramException();
            }
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="existing">Existing key (don't forget to dispose)</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in PrivateKeySuite key, [NotNullWhen(returnValue: true)] out PrivateKeySuite? existing)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PrivateKeys.TryGetValue(name, out existing)) return false;
            PrivateKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If updated (don't forget to dispose)</returns>
        public async Task<TryAsyncResult<PrivateKeySuite>> TryUpdateAsync(string name, PrivateKeySuite key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PrivateKeys.TryGetValue(name, out PrivateKeySuite? existing)) return false;
            PrivateKeys[name] = key;
            return new(existing);
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="existing">Existing key (don't forget to dispose)</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in PublicKeySuite key, [NotNullWhen(returnValue: true)] out PublicKeySuite? existing)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PublicKeys.TryGetValue(name, out existing)) return false;
            PublicKeys[name] = key;
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If updated (don't forget to dispose)</returns>
        public async Task<TryAsyncResult<PublicKeySuite>> TryUpdateAsync(string name, PublicKeySuite key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PublicKeys.TryGetValue(name, out PublicKeySuite? existing)) return false;
            PublicKeys[name] = key;
            return new(existing);
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="existing">Existing key (don't forget to dispose)</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in PrivateKeySuiteStore key, [NotNullWhen(returnValue: true)] out PrivateKeySuiteStore? existing)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PrivateKeySuites.TryGetValue(name, out existing)) return false;
            PrivateKeySuites[name] = key;
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If updated (don't forget to dispose)</returns>
        public async Task<TryAsyncResult<PrivateKeySuiteStore>> TryUpdateAsync(string name, PrivateKeySuiteStore key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PrivateKeySuites.TryGetValue(name, out PrivateKeySuiteStore? existing)) return false;
            PrivateKeySuites[name] = key;
            return new(existing);
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="existing">Existing key (don't forget to dispose)</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in PublicKeySuiteStore key, [NotNullWhen(returnValue: true)] out PublicKeySuiteStore? existing)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PublicKeySuites.TryGetValue(name, out existing)) return false;
            PublicKeySuites[name] = key;
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If updated (don't forget to dispose)</returns>
        public async Task<TryAsyncResult<PublicKeySuiteStore>> TryUpdateAsync(string name, PublicKeySuiteStore key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PublicKeySuites.TryGetValue(name, out PublicKeySuiteStore? existing)) return false;
            PublicKeySuites[name] = key;
            return new(existing);
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="existing">Existing key (don't forget to dispose)</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in PakeRecord key, [NotNullWhen(returnValue: true)] out PakeRecord? existing)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PakeRecords.TryGetValue(name, out existing)) return false;
            PakeRecords[name] = key;
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If updated (don't forget to dispose)</returns>
        public async Task<TryAsyncResult<PakeRecord>> TryUpdateAsync(string name, PakeRecord key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PakeRecords.TryGetValue(name, out PakeRecord? existing)) return false;
            PakeRecords[name] = key;
            return new(existing);
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="existing">Existing key (don't forget to dispose)</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in PakeRecordStore key, [NotNullWhen(returnValue: true)] out PakeRecordStore? existing)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!PakeRecordStores.TryGetValue(name, out existing)) return false;
            PakeRecordStores[name] = key;
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If updated (don't forget to dispose)</returns>
        public async Task<TryAsyncResult<PakeRecordStore>> TryUpdateAsync(string name, PakeRecordStore key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!PakeRecordStores.TryGetValue(name, out PakeRecordStore? existing)) return false;
            PakeRecordStores[name] = key;
            return new(existing);
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="existing">Existing key (don't forget to dispose)</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in SignedPkiStore key, [NotNullWhen(returnValue: true)] out SignedPkiStore? existing)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!Pkis.TryGetValue(name, out existing)) return false;
            Pkis[name] = key;
            return true;
        }

        /// <summary>
        /// Try updating a key
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="key">Key (will be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If updated (don't forget to dispose)</returns>
        public async Task<TryAsyncResult<SignedPkiStore>> TryUpdateAsync(string name, SignedPkiStore key, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!Pkis.TryGetValue(name, out SignedPkiStore? existing)) return false;
            Pkis[name] = key;
            return new(existing);
        }

        /// <summary>
        /// Try updating options
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="options">Options</param>
        /// <param name="existing">Existing options</param>
        /// <returns>If updated</returns>
        public bool TryUpdate(in string name, in CryptoOptions options, [NotNullWhen(returnValue: true)] out CryptoOptions? existing)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = Sync;
            if (!Options.TryGetValue(name, out existing)) return false;
            Options[name] = options;
            return true;
        }

        /// <summary>
        /// Try updating options
        /// </summary>
        /// <param name="name">Name</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If updated</returns>
        public async Task<TryAsyncResult<CryptoOptions>> TryUpdateAsync(string name, CryptoOptions options, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (!Options.TryGetValue(name, out CryptoOptions? existing)) return false;
            Options[name] = options;
            return new(existing);
        }
    }
}
