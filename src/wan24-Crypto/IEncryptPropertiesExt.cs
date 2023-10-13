namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an object which contains methods for extended en-/decryption
    /// </summary>
    public interface IEncryptPropertiesExt : IEncryptProperties
    {
        /// <summary>
        /// Called before encryption
        /// </summary>
        /// <param name="pwd">Key encryption key (KEK; required when there's a DEK property)</param>
        /// <param name="dekLength">Generated DEK length in bytes</param>
        /// <param name="dataEncryptionKey">DEK to use (no DEK property required)</param>
        /// <param name="options">Options</param>
        void BeforeEncrypt(byte[]? pwd, int dekLength, byte[]? dataEncryptionKey, CryptoOptions? options);
        /// <summary>
        /// Called after encryption
        /// </summary>
        /// <param name="pwd">Key encryption key (KEK; required when there's a DEK property)</param>
        /// <param name="dekLength">Generated DEK length in bytes</param>
        /// <param name="dataEncryptionKey">DEK to use (no DEK property required)</param>
        /// <param name="options">Options</param>
        void AfterEncrypt(byte[]? pwd, int dekLength, byte[]? dataEncryptionKey, CryptoOptions? options);
        /// <summary>
        /// Called before decryption
        /// </summary>
        /// <param name="pwd">Key encryption key (KEK; required when there's a DEK property)</param>
        /// <param name="dataEncryptionKey">DEK to use (no DEK property required)</param>
        /// <param name="options">Options</param>
        void BeforeDecrypt(byte[]? pwd, byte[]? dataEncryptionKey, CryptoOptions? options);
        /// <summary>
        /// Called after decryption
        /// </summary>
        /// <param name="pwd">Key encryption key (KEK; required when there's a DEK property)</param>
        /// <param name="dataEncryptionKey">DEK to use (no DEK property required)</param>
        /// <param name="options">Options</param>
        void AfterDecrypt(byte[]? pwd, byte[]? dataEncryptionKey, CryptoOptions? options);
    }
}
