using System.Collections.Concurrent;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Signed PKI store
    /// </summary>
    public class SignedPkiStore : DisposableBase
    {
        /// <summary>
        /// Trusted root keys (key is the keys ID)
        /// </summary>
        protected readonly ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> _RootKeys = new();
        /// <summary>
        /// Keys (key is the keys ID)
        /// </summary>
        protected readonly ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> _Keys = new();
        /// <summary>
        /// Revoked keys (key is the keys ID)
        /// </summary>
        protected readonly ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> _RevokedKeys = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public SignedPkiStore() : this(asyncDisposing: false) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="asyncDisposing">Asynchronous disposing?</param>
        protected SignedPkiStore(bool asyncDisposing) : base(asyncDisposing) { }

        /// <summary>
        /// Trusted root keys (key is the keys ID)
        /// </summary>
        public virtual ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> RootKeys => IfUndisposed(_RootKeys);

        /// <summary>
        /// Keys (key is the keys ID)
        /// </summary>
        public virtual ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> Keys => IfUndisposed(_Keys);

        /// <summary>
        /// Revoked keys (key is the keys ID)
        /// </summary>
        public virtual ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> RevokedKeys => IfUndisposed(_RevokedKeys);

        /// <summary>
        /// Enable this as local PKI
        /// </summary>
        public virtual void EnableLocalPki()
        {
            EnsureUndisposed();
            AsymmetricSignedPublicKey.RootTrust = IsTrustedRoot;
            AsymmetricSignedPublicKey.RootTrustAsync = IsTrustedRootAsync;
            AsymmetricSignedPublicKey.SignedPublicKeyStore = GetKey;
            AsymmetricSignedPublicKey.SignedPublicKeyStoreAsync = GetKeyAsync;
            AsymmetricSignedPublicKey.SignedPublicKeyRevocation = IsKeyRevoked;
            AsymmetricSignedPublicKey.SignedPublicKeyRevocationAsync = IsKeyRevokedAsync;
        }

        /// <summary>
        /// Add a trusted root key
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        public virtual void AddTrustedRoot(AsymmetricSignedPublicKey key)
        {
            try
            {
                EnsureUndisposed();
                if (key.Signer is not null) throw new InvalidOperationException("Key is not self-signed");
                byte[] id = key.PublicKey.ID;
                if (IsKeyRevoked(id)) throw new InvalidOperationException("Key was revoked");
                if (!_RootKeys.Keys.Any(k => k.SequenceEqual(id))) _RootKeys.TryAdd(id, key);
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Add a trusted root key
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public virtual Task AddTrustedRootAsync(AsymmetricSignedPublicKey key, CancellationToken cancellationToken = default)
        {
            AddTrustedRoot(key);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Add a key
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        public virtual void AddKey(AsymmetricSignedPublicKey key)
        {
            try
            {
                EnsureUndisposed();
                if (key.Signer is null) throw new InvalidOperationException("Key is self-signed");
                byte[] id = key.PublicKey.ID;
                if (IsKeyRevoked(id)) throw new InvalidOperationException("Key was revoked");
                if (!_Keys.Keys.Any(k => k.SequenceEqual(id))) _Keys.TryAdd(id, key);
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Add a key
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public virtual Task AddKeyAsync(AsymmetricSignedPublicKey key, CancellationToken cancellationToken = default)
        {
            AddKey(key);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Determine if a key ID is related to a trusted root key
        /// </summary>
        /// <param name="id">ID</param>
        /// <returns>Is a trusted root key ID?</returns>
        public virtual bool IsTrustedRoot(byte[] id)
        {
            EnsureUndisposed();
            return _RootKeys.Keys.Any(k => k.SequenceEqual(id));
        }

        /// <summary>
        /// Determine if a key ID is related to a trusted root key
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Is a trusted root key ID?</returns>
        public virtual Task<bool> IsTrustedRootAsync(byte[] id, CancellationToken cancellationToken = default) => Task.FromResult(IsTrustedRoot(id));

        /// <summary>
        /// Get a key (won't return revoked keys)
        /// </summary>
        /// <param name="id">ID</param>
        /// <returns>Key (do not dispose!)</returns>
        public virtual AsymmetricSignedPublicKey? GetKey(byte[] id)
        {
            EnsureUndisposed();
            AsymmetricSignedPublicKey? res = null;
            if (_Keys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is not byte[] keyId)
            {
                if (_RootKeys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is not byte[] rootKeyId)
                    return null;
                res = _RootKeys.TryGetValue(rootKeyId, out AsymmetricSignedPublicKey? rootKey) ? rootKey : null;
            }
            else
            {
                res = _Keys.TryGetValue(keyId, out AsymmetricSignedPublicKey? key) ? key : null;
            }
            return IsKeyRevoked(id) ? null : res;
        }

        /// <summary>
        /// Get a key (won't return revoked keys)
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key (do not dispose!)</returns>
        public virtual Task<AsymmetricSignedPublicKey?> GetKeyAsync(byte[] id, CancellationToken cancellationToken = default) => Task.FromResult(GetKey(id));

        /// <summary>
        /// Determine if a key ID is related to a revoked key
        /// </summary>
        /// <param name="id">ID</param>
        /// <returns>Is a revoked key ID?</returns>
        public virtual bool IsKeyRevoked(byte[] id)
        {
            EnsureUndisposed();
            return _RevokedKeys.Keys.Any(k => k.SequenceEqual(id));
        }

        /// <summary>
        /// Determine if a key ID is related to a revoked key
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Is a revoked key ID?</returns>
        public virtual Task<bool> IsKeyRevokedAsync(byte[] id, CancellationToken cancellationToken = default) => Task.FromResult(IsKeyRevoked(id));

        /// <summary>
        /// Get a revoked key
        /// </summary>
        /// <param name="id">ID</param>
        /// <returns>Key (do not dispose!)</returns>
        public virtual AsymmetricSignedPublicKey? GetRevokedKey(byte[] id)
        {
            EnsureUndisposed();
            if (_RevokedKeys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is not byte[] keyId) return null;
            return _RevokedKeys.TryGetValue(keyId, out AsymmetricSignedPublicKey? key) ? key : null;
        }

        /// <summary>
        /// Get a revoked key
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key (do not dispose!)</returns>
        public virtual Task<AsymmetricSignedPublicKey?> GetRevokedKeyAsync(byte[] id, CancellationToken cancellationToken = default) => Task.FromResult(GetRevokedKey(id));

        /// <summary>
        /// Revoke a key
        /// </summary>
        /// <param name="id">ID</param>
        /// <returns>If revoked</returns>
        public virtual bool Revoke(byte[] id)
        {
            if (GetKey(id) is not AsymmetricSignedPublicKey key) return false;
            if (_RevokedKeys.TryAdd(key.PublicKey.ID, key))
            {
                if (_RootKeys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is byte[] rootKeyId) _RootKeys.TryRemove(rootKeyId, out _);
                if (_Keys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is byte[] keyId) _Keys.TryRemove(keyId, out _);
            }
            return true;
        }

        /// <summary>
        /// Revoke a key
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If revoked</returns>
        public virtual Task<bool> RevokeAsync(byte[] id, CancellationToken cancellationToken = default) => Task.FromResult(Revoke(id));

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            _RootKeys.Values.DisposeAll();
            _Keys.Values.DisposeAll();
            _RevokedKeys.Values.DisposeAll();
            _RootKeys.Clear();
            _Keys.Clear();
            _RevokedKeys.Clear();
        }
    }
}
