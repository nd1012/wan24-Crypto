using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an encryptable object which provides the key encryption key (KEK) which is going to be used to en-/decrypt the data encryption key (DEK)
    /// </summary>
    public interface IEncryptPropertiesKek : IEncryptProperties
    {
        /// <summary>
        /// Get the key encryption key (KEK)
        /// </summary>
        /// <returns>Key encryption key (don't forget to dispose!)</returns>
        public SecureByteArray GetKeyEncryptionKey();
    }
}
