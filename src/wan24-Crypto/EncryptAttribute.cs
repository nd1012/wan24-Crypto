using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Attribute for a property which can be encrypted/decrypted
    /// </summary>
    [AttributeUsage(AttributeTargets.Property)]
    public class EncryptAttribute : Attribute
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public EncryptAttribute() : base() { }

        /// <summary>
        /// Get the raw data
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pi">Property info</param>
        /// <returns>Raw data</returns>
        public virtual byte[]? GetRaw<T>(T obj, PropertyInfoExt pi) where T : notnull => pi.Getter!(obj) as byte[];

        /// <summary>
        /// Set the raw data
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pi">Property info</param>
        /// <param name="data">Raw data</param>
        public virtual void SetRaw<T>(T obj, PropertyInfoExt pi, byte[] data) where T : notnull => pi.Setter!(obj, data);

        /// <summary>
        /// Get the cipher data
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pi">Property info</param>
        /// <returns>Raw data</returns>
        public virtual byte[]? GetCipher<T>(T obj, PropertyInfoExt pi) where T : notnull => pi.Getter!(obj) as byte[];

        /// <summary>
        /// Set the cipher data
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pi">Property info</param>
        /// <param name="data">Cipher data</param>
        public virtual void SetCipher<T>(T obj, PropertyInfoExt pi, byte[] data) where T : notnull => pi.Setter!(obj, data);
    }
}
