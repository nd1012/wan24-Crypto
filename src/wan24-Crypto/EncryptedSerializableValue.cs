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
            get => StoreDecrypted
                ? _Object ??= RawData is byte[] raw1 ? raw1.ToObject<T>() : null
                : RawData is byte[] raw2 ? raw2.ToObject<T>() : null;
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
    }
}
