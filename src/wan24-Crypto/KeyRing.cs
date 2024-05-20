using System.Collections.Concurrent;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Key ring
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    public sealed partial class KeyRing() : DisposableStreamSerializerBase(VERSION)
    {
        /// <summary>
        /// Thread synchronization
        /// </summary>
        private readonly SemaphoreSync Sync = new();
        /// <summary>
        /// Key names
        /// </summary>
        private readonly ConcurrentDictionary<string, KeyTypes> KeyNames = [];
        /// <summary>
        /// Symmetric keys
        /// </summary>
        private readonly ConcurrentDictionary<string, byte[]> SymmetricKeys = [];
        /// <summary>
        /// Asymmetric private keys
        /// </summary>
        private readonly ConcurrentDictionary<string, IAsymmetricPrivateKey> AsymmetricPrivateKeys = [];
        /// <summary>
        /// Asymmetric public keys
        /// </summary>
        private readonly ConcurrentDictionary<string, IAsymmetricPublicKey> AsymmetricPublicKeys = [];
        /// <summary>
        /// Private keys
        /// </summary>
        private readonly ConcurrentDictionary<string, PrivateKeySuite> PrivateKeys = [];
        /// <summary>
        /// Public keys
        /// </summary>
        private readonly ConcurrentDictionary<string, PublicKeySuite> PublicKeys = [];
        /// <summary>
        /// Private key suites
        /// </summary>
        private readonly ConcurrentDictionary<string, PrivateKeySuiteStore> PrivateKeySuites = [];
        /// <summary>
        /// Public key suites
        /// </summary>
        private readonly ConcurrentDictionary<string, PublicKeySuiteStore> PublicKeySuites = [];
        /// <summary>
        /// PAKE records
        /// </summary>
        private readonly ConcurrentDictionary<string, PakeRecord> PakeRecords = [];
        /// <summary>
        /// PAKE record stores
        /// </summary>
        private readonly ConcurrentDictionary<string, PakeRecordStore> PakeRecordStores = [];
        /// <summary>
        /// PKIs
        /// </summary>
        private readonly ConcurrentDictionary<string, SignedPkiStore> Pkis = [];
        /// <summary>
        /// Crypt options
        /// </summary>
        private readonly ConcurrentDictionary<string, CryptoOptions> Options = [];
        /// <summary>
        /// If to ignore serialization errors when deserializing
        /// </summary>
        private readonly bool IgnoreSerializationErrors = false;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="ignoreSerializationErrors">If to ignore serialization errors when deserializing</param>
        public KeyRing(in bool ignoreSerializationErrors) : this() => IgnoreSerializationErrors = ignoreSerializationErrors;

        /// <summary>
        /// Get a key type
        /// </summary>
        /// <param name="name">Key name</param>
        /// <returns>Key type</returns>
        public KeyTypes this[string name] => KeyNames.TryGetValue(name, out KeyTypes res) ? res : KeyTypes.None;

        /// <summary>
        /// Stored key names
        /// </summary>
        public IEnumerable<string> Names => KeyNames.Keys;

        /// <summary>
        /// Number of stored objects
        /// </summary>
        public int Count => KeyNames.Count;

        /// <summary>
        /// Number of serialized objects (if after deserialization the number is different from <see cref="Count"/>, some incompatible objects have been skipped)
        /// </summary>
        public int SerializedCount { get; private set; }

        /// <summary>
        /// Get stored key names
        /// </summary>
        /// <param name="keyType">Key type</param>
        /// <returns>Stored key names</returns>
        public IEnumerable<string> GetNames(in KeyTypes keyType) => keyType switch
        {
            KeyTypes.Symmetric => SymmetricKeys.Keys,
            KeyTypes.AsymmetricPrivate => AsymmetricPrivateKeys.Keys,
            KeyTypes.AsymmetricPublic => AsymmetricPublicKeys.Keys,
            KeyTypes.PrivateSuite => PrivateKeys.Keys,
            KeyTypes.PublicSuite => PublicKeys.Keys,
            KeyTypes.PrivateSuiteStore => PrivateKeySuites.Keys,
            KeyTypes.PublicSuiteStore => PublicKeySuites.Keys,
            KeyTypes.Pake => PakeRecords.Keys,
            KeyTypes.PakeStore => PakeRecordStores.Keys,
            KeyTypes.Pki => Pkis.Keys,
            _ => throw new ArgumentException("Invalid key type", nameof(keyType))
        };

        /// <summary>
        /// Get the number of stored keys
        /// </summary>
        /// <param name="keyType">Key type</param>
        /// <returns>Number of stored keys</returns>
        public int GetCount(in KeyTypes keyType) => keyType switch
        {
            KeyTypes.Symmetric => SymmetricKeys.Count,
            KeyTypes.AsymmetricPrivate => AsymmetricPrivateKeys.Count,
            KeyTypes.AsymmetricPublic => AsymmetricPublicKeys.Count,
            KeyTypes.PrivateSuite => PrivateKeys.Count,
            KeyTypes.PublicSuite => PublicKeys.Count,
            KeyTypes.PrivateSuiteStore => PrivateKeySuites.Count,
            KeyTypes.PublicSuiteStore => PublicKeySuites.Count,
            KeyTypes.Pake => PakeRecords.Count,
            KeyTypes.PakeStore => PakeRecordStores.Count,
            KeyTypes.Pki => Pkis.Count,
            _ => throw new ArgumentException("Invalid key type", nameof(keyType))
        };

        /// <summary>
        /// Clear all keys
        /// </summary>
        public void Clear()
        {
            using SemaphoreSyncContext ssc = Sync;
            foreach (byte[] key in SymmetricKeys.Values)
                key.Clear();
            SymmetricKeys.Clear();
            AsymmetricPrivateKeys.Values.DisposeAll();
            AsymmetricPrivateKeys.Clear();
            AsymmetricPublicKeys.Values.DisposeAll();
            AsymmetricPublicKeys.Clear();
            PrivateKeys.Values.DisposeAll();
            PrivateKeys.Clear();
            PublicKeys.Values.DisposeAll();
            PublicKeys.Clear();
            PrivateKeySuites.Values.DisposeAll();
            PrivateKeySuites.Clear();
            PublicKeySuites.Values.DisposeAll();
            PublicKeySuites.Clear();
            foreach (PakeRecord rec in PakeRecords.Values)
                rec.Clear();
            PakeRecords.Clear();
            PakeRecordStores.Values.DisposeAll();
            PakeRecordStores.Clear();
            Pkis.Values.DisposeAll();
            Pkis.Clear();
            KeyNames.Clear();
        }

        /// <summary>
        /// Clear all keys
        /// </summary>
        public async Task ClearAsync()
        {
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync().DynamicContext();
            foreach (byte[] key in SymmetricKeys.Values)
                key.Clear();
            SymmetricKeys.Clear();
            await AsymmetricPrivateKeys.Values.DisposeAllAsync().DynamicContext();
            AsymmetricPrivateKeys.Clear();
            await AsymmetricPublicKeys.Values.DisposeAllAsync().DynamicContext();
            AsymmetricPublicKeys.Clear();
            await PrivateKeys.Values.DisposeAllAsync().DynamicContext();
            PrivateKeys.Clear();
            await PublicKeys.Values.DisposeAllAsync().DynamicContext();
            PublicKeys.Clear();
            await PrivateKeySuites.Values.DisposeAllAsync().DynamicContext();
            PrivateKeySuites.Clear();
            await PublicKeySuites.Values.DisposeAllAsync().DynamicContext();
            PublicKeySuites.Clear();
            foreach (PakeRecord rec in PakeRecords.Values)
                rec.Clear();
            PakeRecords.Clear();
            await PakeRecordStores.Values.DisposeAllAsync().DynamicContext();
            PakeRecordStores.Clear();
            await Pkis.Values.DisposeAllAsync().DynamicContext();
            Pkis.Clear();
            KeyNames.Clear();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Clear();
            Sync.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await ClearAsync().DynamicContext();
            await Sync.DisposeAsync().DynamicContext();
        }
    }
}
