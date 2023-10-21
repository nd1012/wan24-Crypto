using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <c>/dev/random</c> readable stream pool
    /// </summary>
    public sealed class DevRandomStreamPool : DisposableObjectPool<Stream>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Capacity</param>
        public DevRandomStreamPool(in int capacity) : base(capacity, RND.GetDevRandom) { }
    }
}
