using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Casting
    public partial record class CryptoOptions
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
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator CryptoOptions(byte[] data) => data.ToObject<CryptoOptions>();

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="options">Options</param>
        public static explicit operator byte[](CryptoOptions options) => options.ToBytes();
    }
}
