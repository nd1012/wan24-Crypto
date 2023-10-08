using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
{
    // Authentication
    public sealed partial class PakeServerAuth
    {
        /// <summary>
        /// Process an authentication
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Context</returns>
        private async Task<PakeAuthContext> ProcessAuthenticationAsync(Stream stream, CancellationToken cancellationToken)
        {
            DecryptionStreams? decipher = null;
            CryptoOptions? cryptoOptions = null;
            byte[]? sessionKey = null;
            PakeServerAuthContext context = new(this, stream);
            try
            {
                if (Options.ClientAuthFactory is null) throw new InvalidOperationException("No client authentication information factory");
                using Pake pake = new(Options.PakeOptions?.GetCopy(), Options.CryptoOptions?.GetCopy());
                pake.OnAuth += (s, e) => OnPakeAuth?.Invoke(this, new(context, pake, e));
                pake.OnAuthError += (s, e) => OnPakeAuthError?.Invoke(this, new(context, pake, e));
                // Receive the identifier, load the client authentication information, receive the random data, create the temporary session key and start decryption
                using (RentedArrayStructSimple<byte> buffer = new(len: ValueLength, clean: false)
                {
                    Clear = true
                })
                {
                    // Load client authentication information
                    if (await stream.ReadAsync(buffer.Memory, cancellationToken).DynamicContext() != ValueLength)
                        throw new IOException("Failed to read the identifier");
                    await Options.ClientAuthFactory(context, buffer.Memory, cancellationToken).DynamicContext();
                    if (context.ClientIdentity is null) throw new InvalidDataException("No client identity");
                    if (context.ServerIdentity is null) throw new InvalidDataException("No server identity");
                    pake.Identity = new PakeRecord(context.ClientIdentity);
                    // Create the session key and start decryption
                    if (await stream.ReadAsync(buffer.Memory, cancellationToken).DynamicContext() != ValueLength)
                        throw new IOException("Failed to read the random data");
                    cryptoOptions = Options.CryptoOptions!.GetCopy();
                    cryptoOptions.Password = pake.CreateSessionKey(context.ServerIdentity.SignatureKey, context.ServerIdentity.Secret, buffer.Span);
                    decipher = await Encryption.GetDecryptionStreamAsync(stream, Stream.Null, cryptoOptions, cancellationToken).DynamicContext();
                }
                // Receive the authentication request
                if (context.FastPakeAuthServer is null)
                {
                    context.ClientPayload = pake.HandleAuth(
                        await decipher.CryptoStream.ReadSerializedAsync<PakeAuth>(cancellationToken: cancellationToken).DynamicContext(),
                        Options.DecryptPayload,
                        Options.SkipSignatureKeyValidation
                        );
                    sessionKey = pake.SessionKey.CloneArray();
                    pake.ClearSessionKey();
                }
                else
                {
                    (context.ClientPayload, sessionKey) = await context.FastPakeAuthServer.HandleAuthAsync(
                        await decipher.CryptoStream.ReadSerializedAsync<PakeAuth>(cancellationToken: cancellationToken).DynamicContext(),
                        Options.DecryptPayload,
                        cancellationToken
                        )
                        .DynamicContext();
                }
                context.ClientTimeOffset = DateTime.UtcNow - context.ClientPayload.Created;
                if (!context.ClientPayload.Created.IsInRange(Options.MaxTimeDifference, DateTime.UtcNow))
                    throw new InvalidDataException("Max. peer time difference exceeded");
                if (Options.AuthenticationHandler is not null) await Options.AuthenticationHandler(context, cancellationToken).DynamicContext();
                if (Options.SendAuthenticationResponse)
                {
                    await stream.WriteAsync((byte)AuthSequences.Authentication, cancellationToken).DynamicContext();
                    await stream.FlushAsync(cancellationToken).DynamicContext();
                }
                await context.ServerIdentity.DisposeAsync().DynamicContext();
                context.ServerIdentity = null;
                return new(context, cryptoOptions.Password.ExtendKey(sessionKey));
            }
            catch
            {
                if (context.ClientIdentity is not null) await context.ClientIdentity.DisposeAsync().DynamicContext();
                if (context.ServerIdentity is not null) await context.ServerIdentity.DisposeAsync().DynamicContext();
                context.ClientPayload?.Payload?.Clear();
                context.ServerPayload?.Clear();
                sessionKey?.Clear();
                throw;
            }
            finally
            {
                if (decipher is not null) await decipher.DisposeAsync().DynamicContext();
                cryptoOptions?.Clear();
            }
        }
    }
}
