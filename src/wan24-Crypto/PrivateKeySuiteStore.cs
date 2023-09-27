using System.Collections.Concurrent;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Private key suite store
    /// </summary>
    public class PrivateKeySuiteStore : DisposableBase
    {
        /// <summary>
        /// Private key suites (key is the suite revision)
        /// </summary>
        protected readonly ConcurrentDictionary<int, PrivateKeySuite> _Suites = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public PrivateKeySuiteStore() : this(asyncDisposing: false) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="asyncDisposing">Asynchronous disposing?</param>
        protected PrivateKeySuiteStore(in bool asyncDisposing) : base(asyncDisposing) { }

        /// <summary>
        /// Private key suites (key is the suite revision)
        /// </summary>
        [SensitiveData]
        public ConcurrentDictionary<int, PrivateKeySuite> Suites => IfUndisposed(_Suites);

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
                if (_Suites.TryAdd(revision, suite)) return;
            }
        }

        /// <summary>
        /// Get a private key suite
        /// </summary>
        /// <param name="revision">Suite revision</param>
        /// <returns>Private key suite (will be disposed)</returns>
        public virtual PrivateKeySuite? GetSuite(in int revision) => _Suites.TryGetValue(revision, out PrivateKeySuite? res) ? res : null;

        /// <summary>
        /// Remove a public key suite
        /// </summary>
        /// <param name="revision">Suite revision</param>
        public virtual void RemoveSuite(in int revision)
        {
            EnsureUndisposed();
            if (_Suites.TryRemove(revision, out PrivateKeySuite? suite))
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
