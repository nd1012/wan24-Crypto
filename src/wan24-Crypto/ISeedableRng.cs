namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a seedable <see cref="IRng"/>
    /// </summary>
    public interface ISeedableRng : IRng, ISeedConsumer
    {
    }
}
