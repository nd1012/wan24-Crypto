using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Casting
    public partial class CryptoOptions
    {
        /// <summary>
        /// Cast as private key suite
        /// </summary>
        /// <param name="options">Options</param>
        public static implicit operator PrivateKeySuite(CryptoOptions options) => options.CreatePrivateKeySuite();

        /// <summary>
        /// Cast as private key suite
        /// </summary>
        /// <param name="options">Options</param>
        public static implicit operator PublicKeySuite(CryptoOptions options) => options.CreatePublicKeySuite();

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="options">Options</param>
        public static implicit operator byte[](CryptoOptions options) => options.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator CryptoOptions(byte[] data) => data.ToObject<CryptoOptions>();
    }
}
