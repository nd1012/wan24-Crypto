using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
{
    // Signup
    public sealed partial class PakeServerAuth
    {
        /// <summary>
        /// Process a signup
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="preSharedSecret">Pre-shared secret</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Context</returns>
        private async Task<PakeAuthContext> ProcessSignupAsync(Stream stream, byte[]? preSharedSecret, CancellationToken cancellationToken)
        {
            PakeAuthRecord? serverIdentity = null;
            byte[]? sessionKey = null;
            PakeSignup? signup = null;
            PakeServerAuthContext context = new(this, stream);
            try
            {
                if (Options.SignupHandler is null) throw new InvalidOperationException("No signup handler");
                signup = await stream.ReadSerializedAsync<PakeSignup>(cancellationToken: cancellationToken).DynamicContext();
                using Pake pake = new(SetMacAlgorithm(signup.Identifier.Length, Options.PakeOptions?.GetCopy() ?? Pake.DefaultOptions), Options.CryptoOptions?.GetCopy());
                pake.OnSignup += (s, e) => OnPakeSignup?.Invoke(this, new(context, pake, e));
                // Receive the client signup request
                context.ClientPayload = pake.HandleSignup(signup);
                context.ClientIdentity = new PakeRecord(pake.Identity);
                context.ClientTimeOffset = DateTime.UtcNow - context.ClientPayload.Created;
                if (!context.ClientPayload.Created.IsInRange(Options.MaxTimeDifference, DateTime.UtcNow))
                    throw new InvalidDataException("Max. peer time difference exceeded");
                if (Options.SignupValidator is not null && !await Options.SignupValidator(context, cancellationToken).DynamicContext())
                    throw new InvalidDataException("Client signup rejected");
                sessionKey = pake.SessionKey.ExtendKey(preSharedSecret);
                // Create the random server identity
                serverIdentity = Options.AuthRecordPool is null
                    ? await PakeAuthRecord.CreateRandomAsync(pake, valueLength: context.ClientIdentity.Identifier.Length).DynamicContext()
                    : Options.AuthRecordPool.GetOne();
                context.ServerIdentity = serverIdentity;
                await Options.SignupHandler(context, cancellationToken).DynamicContext();
                // Create and send the server signup and extend the session key
                using (PakeSignup serverSignup = new())
                {
                    serverSignup.Identifier = serverIdentity.Identifier.CloneArray();
                    serverSignup.Key = serverIdentity.Key.CloneArray();
                    serverSignup.Secret = serverIdentity.RawSecret.CloneArray();
                    serverSignup.Random = await RND.GetBytesAsync(serverIdentity.Identifier.Length).DynamicContext();
                    serverSignup.Payload = context.ServerPayload ?? Array.Empty<byte>();
                    serverSignup.Signature = pake.SignAndCreateSessionKey(
                        serverIdentity.SignatureKey, 
                        serverSignup.Key, 
                        serverSignup.Random, 
                        serverSignup.Payload, 
                        serverSignup.Secret
                        );
                    await stream.WriteAsync((byte)AuthSequences.Signup, cancellationToken).DynamicContext();
                    await stream.WriteSerializedAsync(serverSignup, cancellationToken).DynamicContext();
                    context.ServerPayload = null;
                    sessionKey = sessionKey.ExtendKey(pake.CreateSessionKey(serverIdentity.SignatureKey, serverSignup.Secret, serverSignup.Random));
                }
                await stream.FlushAsync(cancellationToken).DynamicContext();
                return new(context, sessionKey);
            }
            catch
            {
                if (context.ClientIdentity is not null) await context.ClientIdentity.DisposeAsync().DynamicContext();
                if (context.ServerIdentity is not null) await context.ServerIdentity.DisposeAsync().DynamicContext();
                context.ClientPayload?.Payload?.Clear();
                context.ServerPayload?.Clear();
                serverIdentity?.Clear();
                sessionKey?.Clear();
                signup?.Dispose();
                throw;
            }
            finally
            {
                preSharedSecret?.Clear();
            }
        }
    }
}
