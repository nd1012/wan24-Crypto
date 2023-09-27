using System.Collections.Concurrent;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE record store
    /// </summary>
    public class PakeRecordStore : PakeRecordStore<IPakeRecord>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public PakeRecordStore() : base() { }
    }

    /// <summary>
    /// PAKE record store
    /// </summary>
    public class PakeRecordStore<T> : DisposableBase where T : notnull, IPakeRecord
    {
        /// <summary>
        /// PAKE records (key is the identifier)
        /// </summary>
        protected readonly ConcurrentDictionary<byte[], T> _Records = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public PakeRecordStore() : base(asyncDisposing: true) { }

        /// <summary>
        /// PAKE records (key is the identifier)
        /// </summary>
        public ConcurrentDictionary<byte[], T> Records => IfUndisposed(_Records);

        /// <summary>
        /// Add a PAKE record
        /// </summary>
        /// <param name="record">PAKE record (will be cleared/disposed!)</param>
        public void AddRecord(in T record)
        {
            EnsureUndisposed();
            byte[] identifier = record.Identifier;
            for (; ; )
            {
                RemoveRecord(identifier);
                if (_Records.TryAdd(identifier, record)) return;
            }
        }

        /// <summary>
        /// Add a PAKE record
        /// </summary>
        /// <param name="record">PAKE record (will be cleared/disposed!)</param>
        public async Task AddRecordAsync(T record)
        {
            EnsureUndisposed();
            byte[] identifier = record.Identifier;
            for (; ; )
            {
                await RemoveRecordAsync(identifier).DynamicContext();
                if (_Records.TryAdd(identifier, record)) return;
            }
        }

        /// <summary>
        /// Get a PAKE record
        /// </summary>
        /// <param name="identifier">Identifier</param>
        /// <returns>PAKE record (will be cleared/disposed)</returns>
        public T? GetRecord(byte[] identifier)
        {
            EnsureUndisposed();
            byte[]? recordId = _Records.Keys.FirstOrDefault(k => k.SequenceEqual(identifier));
            return recordId is not null && _Records.TryGetValue(recordId, out T? res) ? res : default;
        }

        /// <summary>
        /// Remove a PAKE record
        /// </summary>
        /// <param name="identifier">Identifier</param>
        public void RemoveRecord(byte[] identifier)
        {
            EnsureUndisposed();
            if (_Records.Keys.FirstOrDefault(k => k.SequenceEqual(identifier)) is byte[] suiteId && _Records.TryRemove(suiteId, out T? record))
                record.Dispose();
        }

        /// <summary>
        /// Remove a PAKE record
        /// </summary>
        /// <param name="identifier">Identifier</param>
        public async Task RemoveRecordAsync(byte[] identifier)
        {
            EnsureUndisposed();
            if (_Records.Keys.FirstOrDefault(k => k.SequenceEqual(identifier)) is byte[] suiteId && _Records.TryRemove(suiteId, out T? record))
                await record.DisposeAsync().DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            foreach (T record in _Records.Values) record.Dispose();
            _Records.Clear();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            foreach (T record in _Records.Values) await record.DisposeAsync().DynamicContext();
            _Records.Clear();
        }
    }
}
