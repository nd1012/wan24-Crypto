using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <c>/dev/urandom</c> readable stream pool
    /// </summary>
    public sealed class DevURandomStreamPool : DisposableObjectPool<Stream>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Capacity</param>
        public DevURandomStreamPool(in int capacity) : base(capacity, RND.GetDevUrandom) { }
    }
}
