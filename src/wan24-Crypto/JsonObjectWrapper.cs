using System.Text;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// JSON object wrapper
    /// </summary>
    public sealed class JsonObjectWrapper
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public JsonObjectWrapper() { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="obj">Object</param>
        public JsonObjectWrapper(object? obj) : this() => SetHostedObject(obj);

        /// <summary>
        /// Hosted object type name
        /// </summary>
        public string? HostedObjectType { get; set; }

        /// <summary>
        /// Hosted object
        /// </summary>
        public byte[]? HostedObject { get; set; }

        /// <summary>
        /// Set the hosted object
        /// </summary>
        /// <param name="obj">Object</param>
        public void SetHostedObject(object? obj)
        {
            if (obj == null)
            {
                HostedObjectType = null;
                HostedObject = null;
            }
            else
            {
                HostedObjectType = obj.GetType().ToString();
                HostedObject = JsonHelper.Encode(obj).GetBytes();
            }
        }

        /// <summary>
        /// Get hosted object
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <returns>Object</returns>
        public T? GetHostedObject<T>()
        {
            if (HostedObjectType != null && (TypeHelper.Instance.GetType(HostedObjectType) is not Type type || !typeof(T).IsAssignableFrom(type)))
                if (TypeHelper.Instance.GetType(HostedObjectType) == null)
                {
                    throw new InvalidDataException($"Failed to load type \"{HostedObjectType}\"");
                }
                else
                {
                    throw new ArgumentException($"Can't get type \"{typeof(T)}\" from \"{HostedObjectType}\"", nameof(T));
                }
            return HostedObject == null ? (T?)(object?)HostedObject : JsonHelper.Decode<T>(HostedObject.ToUtf8String());
        }

        /// <summary>
        /// Get hosted object
        /// </summary>
        /// <returns>Object</returns>
        public object? GetHostedObject()
            => HostedObject == null
                ? null
                : JsonHelper.DecodeObject(
                    TypeHelper.Instance.GetType(HostedObjectType ?? throw new InvalidDataException("Missing hosted object type name"))
                        ?? throw new InvalidDataException($"Failed to load type \"{HostedObjectType}\""),
                    HostedObject.ToUtf8String()
                    );
    }
}
