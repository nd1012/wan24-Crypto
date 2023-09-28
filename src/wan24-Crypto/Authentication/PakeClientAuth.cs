using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE client authentication
    /// </summary>
    public static class PakeClientAuth
    {
        /// <summary>
        /// Perform a signup
        /// </summary>
        /// <param name="stream">Stream (must be blocking and encrypted!)</param>
        /// <param name="options">Options (will be disposed!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Context (don't forget to dispose!)</returns>
        public static async Task<PakeAuthContext> SignupAsync(this Stream stream, PakeClientAuthOptions options, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            CryptoOptions? cryptoOptions = null;
            ISymmetricKeySuite? symmetricKey = null;
            PakeSignup? signup = null;
            byte[]? sessionKey = null,
                payload = null;
            try
            {
                if (!options.IsSignup) throw new ArgumentException("Signup options expected", nameof(options));
                // Ensure a symmetric key suite with an identifier
                symmetricKey = options.SymmetricKey is null
                    ? new SymmetricKeySuite(options.Password!, options.Login, options.PakeOptions)
                    : options.SymmetricKey;
                if (symmetricKey.Identifier is null) throw new ArgumentException("Missing identifier in symmetric key suite", nameof(options));
                // Send the signup request
                using (Pake pake = new(symmetricKey))
                {
                    signup = pake.CreateSignup(options.Payload);
                    sessionKey = pake.SessionKey.CloneArray();
                }
                await stream.WriteAsync((byte)AuthSequences.Signup, cancellationToken).DynamicContext();
                await stream.WriteSerializedAsync(signup, cancellationToken).DynamicContext();
                await stream.FlushAsync(cancellationToken).DynamicContext();
                signup.Dispose();
                signup = null;
                // Receive the response signup request and create the context
                AuthSequences sequence = (AuthSequences)await stream.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                switch (sequence)
                {
                    case AuthSequences.Signup:
                        break;
                    case AuthSequences.Error:
                        throw new UnauthorizedAccessException("The server denied the signup");
                    default:
                        throw new InvalidDataException($"Invalid server response sequence {sequence}");
                }
                cryptoOptions = options.CryptoOptions?.Clone() ?? Pake.DefaultCryptoOptions;
                cryptoOptions.Password?.Clear();
                cryptoOptions.Password = sessionKey;
                DecryptionStreams decipher = await EncryptionHelper.GetAlgorithm(cryptoOptions.Algorithm!).GetDecryptionStreamAsync(
                    stream,
                    Stream.Null,
                    cryptoOptions,
                    cancellationToken
                    )
                    .DynamicContext();
                await using (decipher.DynamicContext())
                {
                    signup = await decipher.CryptoStream.ReadSerializedAsync<PakeSignup>(cancellationToken: cancellationToken).DynamicContext();
                    using Pake pake = new(options.PakeOptions);//TODO Get all PAKE values from fast auth server
                    payload = pake.HandleSignup(signup);
                    return new(new PakeRecord(pake.Identity), sessionKey.ExtendKey(pake.SessionKey), payload);
                }
            }
            catch
            {
                payload?.Clear();
                throw;
            }
            finally
            {
                options.Login?.Clear();
                options.Password?.Clear();
                options.PreSharedSecret?.Clear();
                if (options.SymmetricKey is null) symmetricKey?.Dispose();
                sessionKey?.Clear();
                signup?.Dispose();
                cryptoOptions?.Clear();
                options.Dispose();
            }
        }

        /// <summary>
        /// Perform an authentication
        /// </summary>
        /// <param name="stream">Stream (must be blocking!)</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Context (don't forget to dispose!)</returns>
        public static async Task<PakeAuthContext> AuthenticateAsync(this Stream stream, PakeClientAuthOptions options, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            CryptoOptions? cryptoOptions = null;
            ISymmetricKeySuite? symmetricKey = null;
            PakeAuth? auth = null;
            byte[]? sessionKey = null,
                payload = null;
            try
            {
                if (options.IsSignup) throw new ArgumentException("Authentication options expected", nameof(options));
                // Ensure a symmetric key suite with an identifier
                symmetricKey = options.SymmetricKey is null
                    ? new SymmetricKeySuite(options.Password!, options.Login, options.PakeOptions)
                    : options.SymmetricKey;
                if (symmetricKey.Identifier is null) throw new ArgumentException("Missing identifier in symmetric key suite", nameof(options));
                // Send the authentication request
                cryptoOptions = options.CryptoOptions?.Clone() ?? Pake.DefaultCryptoOptions;
                if (options.FastPakeAuthServer is null)
                {
                    using (Pake pake = new(options.PeerIdentity, options.PakeOptions?.Clone(), cryptoOptions))
                    {
                        auth = pake.CreateAuth(options.Payload, options.EncryptPayload);
                        sessionKey = pake.SessionKey.CloneArray();
                    }
                }
                else
                {
                    (auth, sessionKey) = await options.FastPakeAuthClient.CreateAuthAsync(options.Payload, options.EncryptPayload).DynamicContext();
                }
                await stream.WriteAsync((byte)AuthSequences.Signup, cancellationToken).DynamicContext();
                await stream.WriteSerializedAsync(signup, cancellationToken).DynamicContext();
                await stream.FlushAsync(cancellationToken).DynamicContext();
                signup.Dispose();
                signup = null;
                // Receive the response signup request and create the context
                AuthSequences sequence = (AuthSequences)await stream.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                switch (sequence)
                {
                    case AuthSequences.Signup:
                        break;
                    case AuthSequences.Error:
                        throw new UnauthorizedAccessException("The server denied the signup");
                    default:
                        throw new InvalidDataException($"Invalid server response sequence {sequence}");
                }
                cryptoOptions.Password?.Clear();
                cryptoOptions.Password = sessionKey;
                DecryptionStreams decipher = await EncryptionHelper.GetAlgorithm(cryptoOptions.Algorithm!).GetDecryptionStreamAsync(
                    stream,
                    Stream.Null,
                    cryptoOptions,
                    cancellationToken
                    ).DynamicContext();
                await using (decipher.DynamicContext())
                {
                    using Pake pake = new(options.PakeOptions);
                    signup = await decipher.CryptoStream.ReadSerializedAsync<PakeSignup>(cancellationToken: cancellationToken).DynamicContext();
                    payload = pake.HandleSignup(signup);
                    return new(new PakeRecord(pake.Identity), sessionKey.ExtendKey(pake.SessionKey), payload);
                }
            }
            catch
            {
                payload?.Clear();
                throw;
            }
            finally
            {
                options.Login?.Clear();
                options.Password?.Clear();
                options.PreSharedSecret?.Clear();
                if (options.SymmetricKey is null) symmetricKey?.Dispose();
                sessionKey?.Clear();
                signup?.Dispose();
                cryptoOptions?.Clear();
                options.Dispose();
            }
        }
    }
}
