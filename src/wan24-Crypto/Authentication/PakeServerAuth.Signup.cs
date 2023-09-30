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
            PakeServerAuthContext context = new(this, stream);
            try
            {
                if (Options.SignupHandler is null) throw new InvalidOperationException("No signup handler");
                using Pake pake = new(Options.PakeOptions, Options.CryptoOptions);
                pake.OnSignup += (s, e) => OnPakeSignup?.Invoke(this, new(context, pake, e));
                // Receive the client signup request
                context.ClientPayload = pake.HandleSignup(await stream.ReadSerializedAsync<PakeSignup>(cancellationToken: cancellationToken).DynamicContext());
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
                using (PakeSignup signup = new())
                {
                    signup.Identifier = serverIdentity.Identifier.CloneArray();
                    signup.Key = serverIdentity.Key.CloneArray();
                    signup.Secret = serverIdentity.RawSecret.CloneArray();
                    signup.Random = await RND.GetBytesAsync(serverIdentity.Identifier.Length).DynamicContext();
                    signup.Payload = context.ServerPayload ?? Array.Empty<byte>();
                    signup.Signature = pake.SignAndCreateSessionKey(serverIdentity.SignatureKey, signup.Key, signup.Random, signup.Payload, signup.Secret);
                    await stream.WriteAsync((byte)AuthSequences.Signup, cancellationToken).DynamicContext();
                    await stream.WriteSerializedAsync(signup, cancellationToken).DynamicContext();
                    context.ServerPayload = null;
                    sessionKey = sessionKey.ExtendKey(pake.CreateSessionKey(serverIdentity.SignatureKey, signup.Secret, signup.Random));
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
                throw;
            }
            finally
            {
                preSharedSecret?.Clear();
            }
        }
    }
}
