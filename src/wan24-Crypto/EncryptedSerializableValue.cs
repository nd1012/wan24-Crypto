using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Encrypted serializable value
    /// </summary>
    /// <typeparam name="T">Object type</typeparam>
    public class EncryptedSerializableValue<T> : EncryptedValue where T : class, IStreamSerializer, new()
    {
        /// <summary>
        /// Object
        /// </summary>
        protected T? _Object = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public EncryptedSerializableValue() : base() { }

        /// <inheritdoc/>
        public override byte[]? RawData
        {
            get => base.RawData;
            set
            {
                base.RawData = value;
                _Object = default;
            }
        }

        /// <summary>
        /// Object
        /// </summary>
        public virtual T? Object
        {
            get
            {
                if (_Object is not null) return _Object;
                T? res = default;
                if (RawData is byte[] raw)
                    try
                    {
                        res = raw.ToObject<T>();
                        if (StoreDecrypted) _Object = res;
                    }
                    finally
                    {
                        raw.Clear();
                    }
                return res;
            }
            set
            {
                base.RawData = value?.ToBytes();
                if (StoreDecrypted) _Object = value;
            }
        }

        /// <summary>
        /// Current object buffer
        /// </summary>
        public T? CurrentObject => _Object;

        /// <summary>
        /// Cast as object
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator T?(EncryptedSerializableValue<T> value) => value.Object;
    }
}
