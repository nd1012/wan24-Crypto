﻿using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;
using System.ComponentModel;
using wan24.Core;
using wan24.StreamSerializerExtensions;

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
    public class PakeRecordStore<T> : DisposableStreamSerializerBase, IChangeToken, INotifyPropertyChanged where T : notnull, IPakeRecord
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
        /// PAKE records (key is the identifier)
        /// </summary>
        protected readonly ConcurrentDictionary<EquatableArray<byte>, T> _Records = new(new EquatableArray<byte>.EqualityComparer());

        /// <summary>
        /// Constructor
        /// </summary>
        public PakeRecordStore() : base(VERSION) { }

        /// <summary>
        /// PAKE records (key is the identifier)
        /// </summary>
        public ConcurrentDictionary<EquatableArray<byte>, T> Records => IfUndisposed(_Records);

        /// <summary>
        /// Number of PAKE records
        /// </summary>
        public virtual int RecordsCount => IfUndisposed(_Records.Count);

        /// <inheritdoc/>
        public bool HasChanged => ChangeToken.HasChanged;

        /// <inheritdoc/>
        public bool ActiveChangeCallbacks => ChangeToken.ActiveChangeCallbacks;

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
                if (_Records.TryAdd(identifier, record))
                {
                    SetChanged(nameof(RecordsCount));
                    return;
                }
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
                if (_Records.TryAdd(identifier, record))
                {
                    SetChanged(nameof(RecordsCount));
                    return;
                }
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
            return _Records.TryGetValue(identifier, out T? res) ? res : default;
        }

        /// <summary>
        /// Remove and clear/dispose a PAKE record
        /// </summary>
        /// <param name="identifier">Identifier</param>
        public void RemoveRecord(byte[] identifier)
        {
            EnsureUndisposed();
            if (_Records.TryRemove(identifier, out T? record))
            {
                record.Dispose();
                SetChanged(nameof(RecordsCount));
            }
        }

        /// <summary>
        /// Remove and clear/dispose a PAKE record
        /// </summary>
        /// <param name="identifier">Identifier</param>
        public async Task RemoveRecordAsync(byte[] identifier)
        {
            EnsureUndisposed();
            if (_Records.TryRemove(identifier, out T? record))
            {
                await record.DisposeAsync().DynamicContext();
                SetChanged(nameof(RecordsCount));
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
        protected override void Serialize(Stream stream) => stream.WriteArray(_Records.Values.ToArray());

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
            => await stream.WriteArrayAsync(_Records.Values.ToArray(), cancellationToken).DynamicContext();

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            T[] records = stream.ReadArray<T>(version);
            foreach (T record in records) _Records[record.Identifier] = record;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            T[] records = await stream.ReadArrayAsync<T>(version, cancellationToken: cancellationToken).DynamicContext();
            foreach (T record in records) _Records[record.Identifier] = record;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            foreach (T record in _Records.Values) record.Dispose();
            _Records.Clear();
            ChangeToken.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            foreach (T record in _Records.Values) await record.DisposeAsync().DynamicContext();
            _Records.Clear();
            ChangeToken.Dispose();
        }

        /// <inheritdoc/>
        public event PropertyChangedEventHandler? PropertyChanged
        {
            add => ChangeToken.PropertyChanged += value;
            remove => ChangeToken.PropertyChanged -= value;
        }
    }
}
