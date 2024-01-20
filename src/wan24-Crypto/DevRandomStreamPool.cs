using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <c>/dev/random</c> readable stream pool
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="capacity">Capacity</param>
    public sealed class DevRandomStreamPool(in int capacity) : DisposableObjectPool<Stream>(capacity, RND.GetDevRandom)
    {
    }
}
