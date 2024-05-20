using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Static
    public sealed partial class KeyRing
    {
        /// <summary>
        /// Max. number of stored keys
        /// </summary>
        public static int MaxCount { get; set; } = ushort.MaxValue;

        /// <summary>
        /// Max. symmetric key length in bytes
        /// </summary>
        public static int MaxSymmetricKeyLength { get; set; } = short.MaxValue;

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="suite">Private key suite</param>
        public static implicit operator byte[](KeyRing suite) => suite.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator KeyRing(byte[] data) => data.ToObject<KeyRing>();

        /// <summary>
        /// Decrypt a private key suite cipher and deserialize to a private key suite instance
        /// </summary>
        /// <param name="cipher">Cipher</param>
        /// <param name="key">Key</param>
        /// <param name="options">Options</param>
        /// <returns>Private key suite</returns>
        public static KeyRing Decrypt(byte[] cipher, byte[] key, CryptoOptions? options = null) => (KeyRing)cipher.Decrypt(key, options);
    }
}
