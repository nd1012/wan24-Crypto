using System.Collections.Concurrent;
using wan24.Core;
using wan24.StreamSerializerExtensions;

//TODO Use EquatableArray

namespace wan24.Crypto
{
    /// <summary>
    /// Signed PKI store
    /// </summary>
    public class SignedPkiStore : DisposableStreamSerializerBase
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Trusted root keys (key is the keys ID)
        /// </summary>
        protected readonly ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> _RootKeys = new();
        /// <summary>
        /// Granted keys (key is the keys ID)
        /// </summary>
        protected readonly ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> _GrantedKeys = new();
        /// <summary>
        /// Revoked keys (key is the keys ID)
        /// </summary>
        protected readonly ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> _RevokedKeys = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public SignedPkiStore() : base(VERSION) { }

        /// <summary>
        /// Trusted root keys (key is the keys ID)
        /// </summary>
        public virtual ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> RootKeys => IfUndisposed(_RootKeys);

        /// <summary>
        /// Number of trusted root keys
        /// </summary>
        public virtual int RootKeyCount => IfUndisposed(_RootKeys.Count);

        /// <summary>
        /// Granted keys (key is the keys ID)
        /// </summary>
        public virtual ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> GrantedKeys => IfUndisposed(_GrantedKeys);

        /// <summary>
        /// Number of granted keys
        /// </summary>
        public virtual int GrantedKeyCount => IfUndisposed(_GrantedKeys.Count);

        /// <summary>
        /// Revoked keys (key is the keys ID)
        /// </summary>
        public virtual ConcurrentDictionary<byte[], AsymmetricSignedPublicKey> RevokedKeys => IfUndisposed(_RevokedKeys);

        /// <summary>
        /// Number of revoked keys
        /// </summary>
        public virtual int RevokedKeyCount => IfUndisposed(_RevokedKeys.Count);

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
                for(; ; )
                {
                    if (IsTrustedRoot(id)) RemoveTrustedRoot(id);
                    if (_RootKeys.TryAdd(id, key)) break;
                }
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
        /// Remove (and dispose) a trusted root key
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="dispose">Dispose the key?</param>
        /// <returns>Key</returns>
        public virtual AsymmetricSignedPublicKey? RemoveTrustedRoot(byte[] id, bool dispose = true)
        {
            EnsureUndisposed();
            if (_RootKeys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is byte[] keyId && _RootKeys.TryRemove(keyId, out AsymmetricSignedPublicKey? key))
            {
                if (dispose) key.Dispose();
                return key;
            }
            return null;
        }

        /// <summary>
        /// Add a granted key
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        public virtual void AddGrantedKey(AsymmetricSignedPublicKey key)
        {
            try
            {
                EnsureUndisposed();
                if (key.Signer is null) throw new InvalidOperationException("Key is self-signed");
                byte[] id = key.PublicKey.ID;
                if (IsKeyRevoked(id)) throw new InvalidOperationException("Key was revoked");
                for (; ; )
                {
                    RemoveGrantedKey(id);
                    if (_GrantedKeys.TryAdd(id, key)) break;
                }
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Add a granted key
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public virtual Task AddGrantedKeyAsync(AsymmetricSignedPublicKey key, CancellationToken cancellationToken = default)
        {
            AddGrantedKey(key);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Remove (and dispose) a granted key
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="dispose">Dispose the key?</param>
        /// <returns>Key</returns>
        public virtual AsymmetricSignedPublicKey? RemoveGrantedKey(byte[] id, bool dispose = true)
        {
            EnsureUndisposed();
            if (_GrantedKeys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is byte[] keyId && _GrantedKeys.TryRemove(keyId, out AsymmetricSignedPublicKey? key))
            {
                if (dispose) key.Dispose();
                return key;
            }
            return null;
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
            if (IsKeyRevoked(id)) return null;
            if (_GrantedKeys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is not byte[] keyId)
            {
                return _RootKeys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is byte[] rootKeyId &&
                    _RootKeys.TryGetValue(rootKeyId, out AsymmetricSignedPublicKey? rootKey)
                    ? rootKey
                    : null;
            }
            else if(_GrantedKeys.TryGetValue(keyId, out AsymmetricSignedPublicKey? key))
            {
                return key;
            }
            return null;
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
            key = key.GetCopy();
            try
            {
                if (_RevokedKeys.TryAdd(key.PublicKey.ID, key))
                {
                    RemoveTrustedRoot(id);
                    RemoveGrantedKey(id);
                }
                else
                {
                    key.Dispose();
                }
            }
            catch
            {
                key.Dispose();
                throw;
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

        /// <summary>
        /// Remove (and dispose) a revoked key
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="dispose">Dispose the key?</param>
        /// <returns>Key</returns>
        public virtual AsymmetricSignedPublicKey? RemoveRevokedKey(byte[] id, bool dispose = true)
        {
            EnsureUndisposed();
            if (_RevokedKeys.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is byte[] keyId && _RevokedKeys.TryRemove(keyId, out AsymmetricSignedPublicKey? key))
            {
                if (dispose) key.Dispose();
                return key;
            }
            return null;
        }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteArray(_RootKeys.Values.ToArray());
            stream.WriteArray(_GrantedKeys.Values.ToArray());
            stream.WriteArray(_RevokedKeys.Values.ToArray());
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteArrayAsync(_RootKeys.Values.ToArray(), cancellationToken).DynamicContext();
            await stream.WriteArrayAsync(_GrantedKeys.Values.ToArray(), cancellationToken).DynamicContext();
            await stream.WriteArrayAsync(_RevokedKeys.Values.ToArray(), cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            AsymmetricSignedPublicKey[] keys = stream.ReadArray<AsymmetricSignedPublicKey>(version);
            foreach (AsymmetricSignedPublicKey key in keys) _RootKeys[key.PublicKey.ID] = key;
            keys = stream.ReadArray<AsymmetricSignedPublicKey>(version);
            foreach (AsymmetricSignedPublicKey key in keys) _GrantedKeys[key.PublicKey.ID] = key;
            keys = stream.ReadArray<AsymmetricSignedPublicKey>(version);
            foreach (AsymmetricSignedPublicKey key in keys) _RevokedKeys[key.PublicKey.ID] = key;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            AsymmetricSignedPublicKey[] keys = await stream.ReadArrayAsync<AsymmetricSignedPublicKey>(version, cancellationToken: cancellationToken).DynamicContext();
            foreach (AsymmetricSignedPublicKey key in keys) _RootKeys[key.PublicKey.ID] = key;
            keys = await stream.ReadArrayAsync<AsymmetricSignedPublicKey>(version, cancellationToken: cancellationToken).DynamicContext();
            foreach (AsymmetricSignedPublicKey key in keys) _GrantedKeys[key.PublicKey.ID] = key;
            keys = await stream.ReadArrayAsync<AsymmetricSignedPublicKey>(version, cancellationToken: cancellationToken).DynamicContext();
            foreach (AsymmetricSignedPublicKey key in keys) _RevokedKeys[key.PublicKey.ID] = key;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            _RootKeys.Values.DisposeAll();
            _GrantedKeys.Values.DisposeAll();
            _RevokedKeys.Values.DisposeAll();
            _RootKeys.Clear();
            _GrantedKeys.Clear();
            _RevokedKeys.Clear();
        }
    }
}
