using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Networking
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
            stream.WriteByte((byte)AuthSequences.PublicKeyRequest);
            await stream.WriteSerializedAsync(Options.PrivateKeys.Public, cancellationToken).DynamicContext();
            await stream.FlushAsync(cancellationToken).DynamicContext();
        }
    }
}
