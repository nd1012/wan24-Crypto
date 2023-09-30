using System.Collections.Concurrent;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Public key suite store
    /// </summary>
    public class PublicKeySuiteStore : DisposableBase
    {
        /// <summary>
        /// Public key suites (key is the signed public key ID)
        /// </summary>
        protected readonly ConcurrentDictionary<byte[], PublicKeySuite> _Suites = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public PublicKeySuiteStore() : this(asyncDisposing: false) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="asyncDisposing">Asynchronous disposing?</param>
        protected PublicKeySuiteStore(in bool asyncDisposing) : base(asyncDisposing) { }

        /// <summary>
        /// Public key suites (key is the signed public key ID)
        /// </summary>
        public ConcurrentDictionary<byte[], PublicKeySuite> Suites => IfUndisposed(_Suites);

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
                if (_Suites.TryAdd(suiteId, suite)) return;
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
            byte[]? suiteId = _Suites.Keys.FirstOrDefault(k => k.SequenceEqual(id));
            return suiteId is not null && _Suites.TryGetValue(suiteId, out PublicKeySuite? res) ? res : null;
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
            if (_Suites.Keys.FirstOrDefault(k => k.SequenceEqual(id)) is byte[] suiteId && _Suites.TryRemove(suiteId, out PublicKeySuite? suite))
                suite.Dispose();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            _Suites.Values.DisposeAll();
            _Suites.Clear();
        }
    }
}
