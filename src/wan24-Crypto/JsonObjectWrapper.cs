using System.Text;
using wan24.Core;
using wan24.StreamSerializerExtensions;

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
            if (obj is null)
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
            try
            {
                if (HostedObjectType is not null && (TypeHelper.Instance.GetType(HostedObjectType) is not Type type || !typeof(T).IsAssignableFrom(type)))
                    if (TypeHelper.Instance.GetType(HostedObjectType) is null)
                    {
                        throw new InvalidDataException($"Failed to load type \"{HostedObjectType}\"");
                    }
                    else
                    {
                        throw new ArgumentException($"Can't get type \"{typeof(T)}\" from \"{HostedObjectType}\"", nameof(T));
                    }
                return HostedObject is null ? (T?)(object?)HostedObject : JsonHelper.Decode<T>(HostedObject.ToUtf8String());
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Get hosted object
        /// </summary>
        /// <returns>Object</returns>
        public object? GetHostedObject()
        {
            try
            {
                return HostedObject is null
                    ? null
                    : JsonHelper.DecodeObject(
                        TypeHelper.Instance.GetType(HostedObjectType ?? throw new InvalidDataException("Missing hosted object type name"))
                            ?? throw new InvalidDataException($"Failed to load type \"{HostedObjectType}\""),
                        HostedObject.ToUtf8String()
                        );
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="wrapper">JSON object wrapper</param>
        public static implicit operator byte[](JsonObjectWrapper wrapper) => JsonHelper.Encode(wrapper).GetBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator JsonObjectWrapper(byte[] data) => JsonHelper.Decode<JsonObjectWrapper>(data.ToUtf8String())
            ?? throw new InvalidDataException("Failed to deserialize JSON object wrapper instance");
    }
}
