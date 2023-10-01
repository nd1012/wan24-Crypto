using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
{
    // Public key request
    public sealed partial class ServerAuth
    {
        /// <summary>
        /// Process a public key request
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private async Task ProcessPublicKeyRequestAsync(Stream stream, CancellationToken cancellationToken)
        {
            await ValidateProtocolVersionAsync(stream, cancellationToken).DynamicContext();
            await stream.WriteAsync((byte)AuthSequences.PublicKeyRequest, cancellationToken).DynamicContext();
            await stream.WriteSerializedAsync(Options.PrivateKeys.Public, cancellationToken).DynamicContext();
            await stream.FlushAsync(cancellationToken).DynamicContext();
        }
    }
}
