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
            get => StoreDecrypted
                ? _Object ??= RawData is byte[] raw1 ? JsonHelper.Decode<T>(raw1.ToUtf8String()) : default
                : RawData is byte[] raw2 ? JsonHelper.Decode<T>(raw2.ToUtf8String()) : default;
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
    }
}
