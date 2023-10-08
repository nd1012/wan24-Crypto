namespace wan24.Crypto
{
    // Interception
    public sealed partial record class CryptoOptions
    {
        /// <summary>
        /// Delegate for a <see cref="OnInstanced"/> event handler
        /// </summary>
        /// <param name="options">Options instance</param>
        /// <param name="e">Arguments</param>
        public delegate void Instanced_Delegate(CryptoOptions options, EventArgs e);
        /// <summary>
        /// Raised when a new instance of <see cref="CryptoOptions"/> was created
        /// </summary>
        public static event Instanced_Delegate? OnInstanced;
    }
}
