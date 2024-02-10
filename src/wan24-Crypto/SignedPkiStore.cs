using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using wan24.Core;
using wan24.StreamSerializerExtensions;

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
        protected readonly ConcurrentDictionary<EquatableArray<byte>, AsymmetricSignedPublicKey> _RootKeys = new(new EquatableArray<byte>.EqualityComparer());
        /// <summary>
        /// Granted keys (key is the keys ID)
        /// </summary>
        protected readonly ConcurrentDictionary<EquatableArray<byte>, AsymmetricSignedPublicKey> _GrantedKeys = new(new EquatableArray<byte>.EqualityComparer());
        /// <summary>
        /// Revoked keys (key is the keys ID)
        /// </summary>
        protected readonly ConcurrentDictionary<EquatableArray<byte>, AsymmetricSignedPublicKey> _RevokedKeys = new(new EquatableArray<byte>.EqualityComparer());

        /// <summary>
        /// Constructor
        /// </summary>
        public SignedPkiStore() : base(VERSION) { }

        /// <summary>
        /// Trusted root keys (key is the keys ID)
        /// </summary>
        public virtual ConcurrentDictionary<EquatableArray<byte>, AsymmetricSignedPublicKey> RootKeys => IfUndisposed(_RootKeys);

        /// <summary>
        /// Number of trusted root keys
        /// </summary>
        public virtual int RootKeyCount => IfUndisposed(_RootKeys.Count);

        /// <summary>
        /// Granted keys (key is the keys ID)
        /// </summary>
        public virtual ConcurrentDictionary<EquatableArray<byte>, AsymmetricSignedPublicKey> GrantedKeys => IfUndisposed(_GrantedKeys);

        /// <summary>
        /// Number of granted keys
        /// </summary>
        public virtual int GrantedKeyCount => IfUndisposed(_GrantedKeys.Count);

        /// <summary>
        /// Revoked keys (key is the keys ID)
        /// </summary>
        public virtual ConcurrentDictionary<EquatableArray<byte>, AsymmetricSignedPublicKey> RevokedKeys => IfUndisposed(_RevokedKeys);

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
            if (_RootKeys.TryRemove(id, out AsymmetricSignedPublicKey? key))
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
            if (_GrantedKeys.TryRemove(id, out AsymmetricSignedPublicKey? key))
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
            return _RootKeys.Keys.Any(k => k == id);
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
            if (_GrantedKeys.TryGetValue(id, out AsymmetricSignedPublicKey? key)) return key;
            return _RootKeys.TryGetValue(id, out AsymmetricSignedPublicKey? rootKey)
                ? rootKey
                : null;
        }

        /// <summary>
        /// Get a key (won't return revoked keys)
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key (do not dispose!)</returns>
        public virtual Task<AsymmetricSignedPublicKey?> GetKeyAsync(byte[] id, CancellationToken cancellationToken = default) => Task.FromResult(GetKey(id));

        /// <summary>
        /// Get keys which have been signed by a key (won't return revoked keys)
        /// </summary>
        /// <param name="id">Signer ID</param>
        /// <returns>Signed keys (do not dispose!)</returns>
        public virtual IEnumerable<AsymmetricSignedPublicKey> GetSignedKeys(byte[] id)
        {
            EnsureUndisposed();
            foreach (KeyValuePair<EquatableArray<byte>, AsymmetricSignedPublicKey> kvp in _RootKeys)
                if (kvp.Key == id)
                    yield return kvp.Value;
            foreach (KeyValuePair<EquatableArray<byte>, AsymmetricSignedPublicKey> kvp in _GrantedKeys)
                if (kvp.Key == id)
                    yield return kvp.Value;
        }

        /// <summary>
        /// Get keys which have been signed by a key (won't return revoked keys)
        /// </summary>
        /// <param name="id">Signer ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Signed keys (do not dispose!)</returns>
        public virtual async IAsyncEnumerable<AsymmetricSignedPublicKey> GetSignedKeysAsync(byte[] id, [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            await Task.Yield();
            foreach (KeyValuePair<EquatableArray<byte>, AsymmetricSignedPublicKey> kvp in _RootKeys)
                if (kvp.Key == id)
                    yield return kvp.Value;
            foreach (KeyValuePair<EquatableArray<byte>, AsymmetricSignedPublicKey> kvp in _GrantedKeys)
                if (kvp.Key == id)
                    yield return kvp.Value;
        }

        /// <summary>
        /// Determine if a key ID is related to a revoked key
        /// </summary>
        /// <param name="id">ID</param>
        /// <returns>Is a revoked key ID?</returns>
        public virtual bool IsKeyRevoked(byte[] id)
        {
            EnsureUndisposed();
            return _RevokedKeys.Keys.Any(k => k == id);
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
            return _RevokedKeys.TryGetValue(id, out AsymmetricSignedPublicKey? key) ? key : null;
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
        /// <param name="recursive">Remove signed keys also?</param>
        /// <returns>If revoked</returns>
        public virtual bool Revoke(byte[] id, bool recursive = true)
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
                if (recursive)
                    foreach (AsymmetricSignedPublicKey signedKey in GetSignedKeys(id))
                        Revoke(signedKey.PublicKey.ID);
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
        /// <param name="recursive">Remove signed keys also?</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If revoked</returns>
        public virtual Task<bool> RevokeAsync(byte[] id, bool recursive = true, CancellationToken cancellationToken = default) => Task.FromResult(Revoke(id, recursive));

        /// <summary>
        /// Remove (and dispose) a revoked key
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="dispose">Dispose the key?</param>
        /// <returns>Key</returns>
        public virtual AsymmetricSignedPublicKey? RemoveRevokedKey(byte[] id, bool dispose = true)
        {
            EnsureUndisposed();
            if (_RevokedKeys.TryRemove(id, out AsymmetricSignedPublicKey? key))
            {
                if (dispose) key.Dispose();
                return key;
            }
            return null;
        }

        /// <summary>
        /// Get the type of a key within this PKI
        /// </summary>
        /// <param name="id">ID</param>
        /// <returns>Key type</returns>
        public virtual AsymmetricSignedPublicKeyTypes GetKeyType(byte[] id)
        {
            EnsureUndisposed();
            AsymmetricSignedPublicKey? key = GetKey(id);
            if (key is null)
            {
                key = GetRevokedKey(id);
                if (key is null) return AsymmetricSignedPublicKeyTypes.Unknown;
                if (key.Type < AsymmetricSignedPublicKeyTypes.End)
                    return (key.Signer is null ? AsymmetricSignedPublicKeyTypes.Root : AsymmetricSignedPublicKeyTypes.Intermediate) | AsymmetricSignedPublicKeyTypes.Revoked;
                return AsymmetricSignedPublicKeyTypes.End | AsymmetricSignedPublicKeyTypes.Revoked;
            }
            if (key.Type < AsymmetricSignedPublicKeyTypes.End) return IsTrustedRoot(id) ? AsymmetricSignedPublicKeyTypes.Root : AsymmetricSignedPublicKeyTypes.Intermediate;
            return AsymmetricSignedPublicKeyTypes.End;
        }

        /// <summary>
        /// Get the type of a key within this PKI
        /// </summary>
        /// <param name="id">ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Key type</returns>
        public virtual async Task<AsymmetricSignedPublicKeyTypes> GetKeyTypeAsync(byte[] id, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            AsymmetricSignedPublicKey? key = await GetKeyAsync(id, cancellationToken).DynamicContext();
            if (key is null)
            {
                key = await GetRevokedKeyAsync(id, cancellationToken).DynamicContext();
                if (key is null) return AsymmetricSignedPublicKeyTypes.Unknown;
                if (key.Type < AsymmetricSignedPublicKeyTypes.End)
                    return (key.Signer is null ? AsymmetricSignedPublicKeyTypes.Root : AsymmetricSignedPublicKeyTypes.Intermediate) | AsymmetricSignedPublicKeyTypes.Revoked;
                return AsymmetricSignedPublicKeyTypes.End | AsymmetricSignedPublicKeyTypes.Revoked;
            }
            if (key.Type < AsymmetricSignedPublicKeyTypes.End) return IsTrustedRoot(id) ? AsymmetricSignedPublicKeyTypes.Root : AsymmetricSignedPublicKeyTypes.Intermediate;
            return AsymmetricSignedPublicKeyTypes.End;
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

        /// <inheritdoc/>
        protected override Task DisposeCore()
        {
            _RootKeys.Values.DisposeAll();
            _GrantedKeys.Values.DisposeAll();
            _RevokedKeys.Values.DisposeAll();
            _RootKeys.Clear();
            _GrantedKeys.Clear();
            _RevokedKeys.Clear();
            return Task.CompletedTask;
        }
    }
}
