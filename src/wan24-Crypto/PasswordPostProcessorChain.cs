using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Password post-processor chain
    /// </summary>
    /// <remarks>
    /// Constructors
    /// </remarks>
    /// <param name="processors">Password post-processors to apply sequential</param>
    public class PasswordPostProcessorChain(params PasswordPostProcessor[] processors) : PasswordPostProcessor()
    {
        /// <summary>
        /// Sequential applied password post-processors
        /// </summary>
        public PasswordPostProcessor[] Processors { get; } = processors;

        /// <inheritdoc/>
        public override byte[] PostProcess(byte[] pwd)
        {
            byte[] res = pwd;
            try
            {
                for (int i = 0, len = Processors.Length; i < len; res = Processors[i].PostProcess(res), i++) ;
            }
            catch(Exception ex)
            {
                res.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            return res;
        }
    }
}
