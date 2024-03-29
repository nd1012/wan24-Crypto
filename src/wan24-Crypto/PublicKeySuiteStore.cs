﻿using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;
using System.ComponentModel;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Public key suite store
    /// </summary>
    public class PublicKeySuiteStore : DisposableStreamSerializerBase, IChangeToken, INotifyPropertyChanged
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Change token
        /// </summary>
        protected readonly DisposableChangeToken ChangeToken = new();
        /// <summary>
        /// Public key suites (key is the signed public key ID)
        /// </summary>
        protected readonly ConcurrentDictionary<EquatableArray<byte>, PublicKeySuite> _Suites = new(new EquatableArray<byte>.EqualityComparer());

        /// <summary>
        /// Constructor
        /// </summary>
        public PublicKeySuiteStore() : base(VERSION) { }

        /// <summary>
        /// Public key suites (key is the signed public key ID)
        /// </summary>
        public virtual ConcurrentDictionary<EquatableArray<byte>, PublicKeySuite> Suites => IfUndisposed(_Suites);

        /// <summary>
        /// Number of public key suites
        /// </summary>
        public virtual int SuiteCount => IfUndisposed(_Suites.Count);

        /// <inheritdoc/>
        public bool HasChanged => ChangeToken.HasChanged;

        /// <inheritdoc/>
        public bool ActiveChangeCallbacks => ChangeToken.ActiveChangeCallbacks;

        /// <summary>
        /// Add a public key suite
        /// </summary>
        /// <param name="suite">Public key suite (requires a signed public key; will be disposed!)</param>
        public virtual void AddSuite(in PublicKeySuite suite)
        {
            EnsureUndisposed();
            if (suite.SignedPublicKey is null) throw new ArgumentException("Signed public key missing", nameof(suite));
            byte[] suiteId = suite.SignedPublicKey.PublicKey.ID;
            for (; ; )
            {
                RemoveSuite(suiteId);
                if (_Suites.TryAdd(suiteId, suite))
                {
                    SetChanged(nameof(SuiteCount));
                    return;
                }
            }
        }

        /// <summary>
        /// Get a public key suite
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        /// <returns>Public key suite (will be disposed)</returns>
        public virtual PublicKeySuite? GetSuite(byte[] id)
        {
            EnsureUndisposed();
            return _Suites.TryGetValue(id, out PublicKeySuite? res) ? res : null;
        }

        /// <summary>
        /// Get a public key suite by an attribute
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="value">Value</param>
        /// <returns>Public key suite (will be disposed)</returns>
        public virtual PublicKeySuite? GetSuiteByAttribute(string key, string value)
        {
            EnsureUndisposed();
            return _Suites.Values.FirstOrDefault(s => s.SignedPublicKey!.Attributes.TryGetValue(key, out string? v) && v == value);
        }

        /// <summary>
        /// Get a public key suites by an attribute
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="value">Value</param>
        /// <returns>Public key suites (will be disposed)</returns>
        public virtual IEnumerable<PublicKeySuite> GetSuitesByAttribute(string key, string value)
        {
            EnsureUndisposed();
            return _Suites.Values.Where(s => s.SignedPublicKey!.Attributes.TryGetValue(key, out string? v) && v == value);
        }

        /// <summary>
        /// Remove and dispose a public key suite
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        public virtual void RemoveSuite(byte[] id)
        {
            EnsureUndisposed();
            if (_Suites.TryRemove(id, out PublicKeySuite? suite))
            {
                suite.Dispose();
                SetChanged(nameof(SuiteCount));
            }
        }

        /// <inheritdoc/>
        public IDisposable RegisterChangeCallback(Action<object?> callback, object? state) => ChangeToken.RegisterChangeCallback(callback, state);

        /// <summary>
        /// Set changed
        /// </summary>
        /// <param name="propertyName">Property name</param>
        protected virtual void SetChanged(in string propertyName)
        {
            ChangeToken.InvokeCallbacks();
            ChangeToken.RaisePropertyChanged(propertyName);
        }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream) => stream.WriteArray(_Suites.Values.ToArray());

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
            => await stream.WriteArrayAsync(_Suites.Values.ToArray(), cancellationToken).DynamicContext();

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            PublicKeySuite[] suites = stream.ReadArray<PublicKeySuite>(version);
            foreach (PublicKeySuite suite in suites) _Suites[suite.SignedPublicKey!.PublicKey.ID] = suite;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            PublicKeySuite[] suites = await stream.ReadArrayAsync<PublicKeySuite>(version, cancellationToken: cancellationToken).DynamicContext();
            foreach (PublicKeySuite suite in suites) _Suites[suite.SignedPublicKey!.PublicKey.ID] = suite;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            _Suites.Values.DisposeAll();
            _Suites.Clear();
            ChangeToken.Dispose();
        }

        /// <inheritdoc/>
        protected override Task DisposeCore()
        {
            _Suites.Values.DisposeAll();
            _Suites.Clear();
            ChangeToken.Dispose();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public event PropertyChangedEventHandler? PropertyChanged
        {
            add => ChangeToken.PropertyChanged += value;
            remove => ChangeToken.PropertyChanged -= value;
        }
    }
}
