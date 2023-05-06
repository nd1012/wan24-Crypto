using System.Text;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Encrypted JSON value
    /// </summary>
    /// <typeparam name="T">Object type</typeparam>
    public class EncryptedJsonValue<T> : EncryptedValue
    {
        /// <summary>
        /// Object
        /// </summary>
        protected T? _Object = default;

        /// <summary>
        /// Constructor
        /// </summary>
        public EncryptedJsonValue() : base() { }

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
                if (_Object != null) return _Object;
                T? res = default;
                if(RawData is byte[] raw)
                    try
                    {
                        res = JsonHelper.Decode<T>(raw.ToUtf8String());
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
                base.RawData = value == null ? null : JsonHelper.Encode(value).GetBytes();
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
        public static implicit operator T?(EncryptedJsonValue<T> value) => value.Object;
    }
}
