using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;
using System.ComponentModel;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Private key suite store
    /// </summary>
    public class PrivateKeySuiteStore : DisposableStreamSerializerBase, IChangeToken, INotifyPropertyChanged
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
        /// Private key suites (key is the suite revision)
        /// </summary>
        protected readonly ConcurrentDictionary<int, PrivateKeySuite> _Suites = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public PrivateKeySuiteStore() : base(VERSION) { }

        /// <summary>
        /// Get a revision
        /// </summary>
        /// <param name="revision">Revision</param>
        /// <returns>Private key suite</returns>
        public PrivateKeySuite this[in int revision] => GetSuite(revision) ?? throw new KeyNotFoundException($"Private key suite #{revision} not found");

        /// <summary>
        /// Private key suites (key is the suite revision)
        /// </summary>
        public ConcurrentDictionary<int, PrivateKeySuite> Suites => IfUndisposed(_Suites);

        /// <summary>
        /// Number of private key suites
        /// </summary>
        public virtual int SuiteCount => IfUndisposed(_Suites.Count);

        /// <summary>
        /// Latest revision
        /// </summary>
        public int LatestRevision => IfUndisposed(() => _Suites.Keys.Cast<int?>().OrderByDescending(k => k).FirstOrDefault() ?? throw new InvalidOperationException("No revisions"));

        /// <summary>
        /// Latest private key suite
        /// </summary>
        public PrivateKeySuite LatestSuite
            => IfUndisposed(() => _Suites.Cast<KeyValuePair<int, PrivateKeySuite>?>().OrderByDescending(kvp => kvp?.Key).Select(kvp => kvp?.Value).FirstOrDefault() ?? throw new InvalidOperationException("No suites"));

        /// <inheritdoc/>
        public bool HasChanged => ChangeToken.HasChanged;

        /// <inheritdoc/>
        public bool ActiveChangeCallbacks => ChangeToken.ActiveChangeCallbacks;

        /// <summary>
        /// Add a private key suite
        /// </summary>
        /// <param name="suite">Private key suite (will be disposed!)</param>
        /// <param name="revision">Suite revision</param>
        public virtual void AddSuite(in PrivateKeySuite suite, in int revision)
        {
            EnsureUndisposed();
            for (; ; )
            {
                RemoveSuite(revision);
                if (_Suites.TryAdd(revision, suite))
                {
                    SetChanged(nameof(SuiteCount));
                    return;
                }
            }
        }

        /// <summary>
        /// Get a private key suite
        /// </summary>
        /// <param name="revision">Suite revision</param>
        /// <returns>Private key suite (will be disposed)</returns>
        public virtual PrivateKeySuite? GetSuite(in int revision) => _Suites.TryGetValue(revision, out PrivateKeySuite? res) ? res : null;

        /// <summary>
        /// Get a private key suite
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        /// <returns>Private key suite (will be disposed)</returns>
        public virtual PrivateKeySuite? GetSuite(byte[] id)
        {
            EnsureUndisposed();
            return _Suites.Values.FirstOrDefault(s => s.SignedPublicKey?.PublicKey.ID.SequenceEqual(id) ?? false);
        }

        /// <summary>
        /// Remove and dispose a private key suite
        /// </summary>
        /// <param name="revision">Suite revision</param>
        public virtual void RemoveSuite(in int revision)
        {
            EnsureUndisposed();
            if (_Suites.TryRemove(revision, out PrivateKeySuite? suite))
            {
                suite.Dispose();
                SetChanged(nameof(SuiteCount));
            }
        }

        /// <summary>
        /// Remove and dispose a private key suite
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        public virtual void RemoveSuite(byte[] id)
        {
            EnsureUndisposed();
            if (
                _Suites.FirstOrDefault(kvp => kvp.Value.SignedPublicKey?.PublicKey.ID.SequenceEqual(id) ?? false) is KeyValuePair<int, PrivateKeySuite> kvp &&
                _Suites.TryRemove(kvp.Key, out PrivateKeySuite? suite)
                )
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
        protected override void Serialize(Stream stream) => stream.WriteDict(new Dictionary<int, PrivateKeySuite>(_Suites));

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
            => await stream.WriteDictAsync(new Dictionary<int, PrivateKeySuite>(_Suites), cancellationToken).DynamicContext();

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            Dictionary<int, PrivateKeySuite> suites = stream.ReadDict<int, PrivateKeySuite>(version);
            foreach (KeyValuePair<int, PrivateKeySuite> kvp in suites) _Suites[kvp.Key] = kvp.Value;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            Dictionary<int, PrivateKeySuite> suites = await stream.ReadDictAsync<int, PrivateKeySuite>(version, cancellationToken: cancellationToken).DynamicContext();
            foreach (KeyValuePair<int, PrivateKeySuite> kvp in suites) _Suites[kvp.Key] = kvp.Value;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            _Suites.Values.DisposeAll();
            _Suites.Clear();
        }

        /// <inheritdoc/>
        protected override Task DisposeCore()
        {
            _Suites.Values.DisposeAll();
            _Suites.Clear();
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
