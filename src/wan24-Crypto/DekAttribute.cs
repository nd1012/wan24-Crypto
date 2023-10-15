using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Attribute for a data encryption key (DEK) of an object
    /// </summary>
    [AttributeUsage(AttributeTargets.Property)]
    public class DekAttribute : Attribute
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public DekAttribute() : base() { }

        /// <summary>
        /// Get the DEK
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pi">Property info</param>
        /// <returns>DEK</returns>
        public virtual byte[]? GetValue<T>(T obj, PropertyInfoExt pi) where T : notnull => pi.Getter!(obj) as byte[];

        /// <summary>
        /// Set the DEK
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pi">Property info</param>
        /// <param name="dek">DEK</param>
        public virtual void SetValue<T>(T obj, PropertyInfoExt pi, byte[] dek) where T : notnull => pi.Setter!(obj, dek);
    }
}
