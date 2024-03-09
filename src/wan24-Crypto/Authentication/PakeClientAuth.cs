using wan24.Core;
using wan24.ObjectValidation;
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
        public static async Task<PakeAuthContext> SignupAsync(this Stream stream, PakeClientAuthOptions? options = null, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            options ??= PakeClientAuthOptions.DefaultOptions ?? throw new ArgumentNullException(nameof(options));
#pragma warning disable CA1859 // Avoid interface
            ISymmetricKeySuite? symmetricKey = null;
#pragma warning restore CA1859 // Avoid interface
            PakeSignup? signup = null;
            PakeRecord? identity = null;
            byte[]? sessionKey = null,
                signatureKey = null,
                payload = null;
            try
            {
                if (!options.IsSignup) throw new ArgumentException("Signup options expected", nameof(options));
                options.PakeOptions?.ValidateAlgorithms();
                options.CryptoOptions?.ValidateAlgorithms();
                // Ensure a symmetric key suite with an identifier
                symmetricKey = options.SymmetricKey is null
                    ? new SymmetricKeySuite(options.Password!, options.Login, options.PakeOptions)
                    : new SymmetricKeySuite(options.SymmetricKey);
                if (symmetricKey.Identifier is null) throw new ArgumentException("Missing identifier in symmetric key suite", nameof(options));
                // Send the signup request
                using Pake pake = new(symmetricKey, options.PakeOptions);
                signup = pake.CreateSignup(new AuthPayload(options.Payload));
                sessionKey = pake.SessionKey.ExtendKey(options.PreSharedSecret);
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
                signup = await stream.ReadSerializedAsync<PakeSignup>(cancellationToken: cancellationToken).DynamicContext();
                signatureKey = pake.CreateSignatureKey(signup.Key, signup.Secret);
                return new(
                    options,
                    sessionKey.ExtendKey(pake.CreateSessionKey(signatureKey, signup.Secret, signup.Random)), 
                    payload, 
                    new PakeAuthRecord(signup, signatureKey)
                    );
            }
            catch
            {
                payload?.Clear();
                signatureKey?.Clear();
                sessionKey?.Clear();
                throw;
            }
            finally
            {
                symmetricKey?.Dispose();
                signup?.Dispose();
                identity?.Clear();
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
        public static async Task<PakeAuthContext> AuthenticateAsync(this Stream stream, PakeClientAuthOptions? options = null, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            options ??= PakeClientAuthOptions.DefaultOptions ?? throw new ArgumentNullException(nameof(options));
            EncryptionStreams? cipher = null;
#pragma warning disable CA1859 // Avoid interface
            ISymmetricKeySuite? symmetricKey = null;
#pragma warning restore CA1859 // Avoid interface
            PakeAuth? auth = null;
            byte[]? serverRandom = null,
                sessionKey = null;
            CryptoOptions cryptoOptions = options.CryptoOptions?.GetCopy() ?? Pake.DefaultCryptoOptions;
            cryptoOptions.ValidateAlgorithms();
            cryptoOptions.LeaveOpen = true;
            EncryptionAlgorithmBase encryption;
            try
            {
                options.PakeOptions?.ValidateAlgorithms();
                if (options.IsSignup) throw new ArgumentException("Authentication options expected", nameof(options));
                if (options.PeerIdentity is null) throw new ArgumentException("Missing peer identity", nameof(options));
                if (options.SymmetricKey is not null && options.SymmetricKey.Identifier is null)
                    throw new ArgumentException("Missing identifier in symmetric key suite", nameof(options));
                // Create the server random data and session key, send the authentication options and start encryption
                serverRandom = await RND.GetBytesAsync(options.PeerIdentity.Identifier.Length);
                await stream.WriteAsync((byte)AuthSequences.Authentication, cancellationToken).DynamicContext();
                await stream.WriteAsync(options.PeerIdentity.Identifier, cancellationToken).DynamicContext();
                await stream.WriteAsync(serverRandom, cancellationToken).DynamicContext();
                cryptoOptions.Password?.Clear();
                cryptoOptions.SetNewPassword(serverRandom.Mac(options.PeerIdentity.SignatureKey.Mac(options.PeerIdentity.Secret, options.PakeOptions), options.PakeOptions));
                cryptoOptions.LeaveOpen = true;
                encryption = EncryptionHelper.GetAlgorithm(cryptoOptions.Algorithm!);
                if (encryption.RequireMacAuthentication)
                    throw new ArgumentException("A cipher which requires MAC authentication isn't supported", nameof(options));
                cipher = await encryption.GetEncryptionStreamAsync(
                    Stream.Null,
                    stream,
                    macStream: null,
                    cryptoOptions,
                    cancellationToken)
                    .DynamicContext();
                // Create the client authentication, send it and extend the session key
                if (options.FastPakeAuthClient is null)
                {
                    // Ensure a symmetric key suite with an identifier
                    symmetricKey = options.SymmetricKey is null
                        ? new SymmetricKeySuite(options.Password!, options.Login, options.PakeOptions?.GetCopy())
                        : new SymmetricKeySuite(options.SymmetricKey, options.PakeOptions?.GetCopy());
                    // Create the authentication and store the session key
                    using Pake pake = new(symmetricKey, options.PakeOptions?.GetCopy(), options.CryptoOptions?.GetCopy());
                    auth = pake.CreateAuth(new AuthPayload(options.Payload), options.EncryptPayload);
                    sessionKey = pake.SessionKey.CloneArray();
                }
                else
                {
                    (auth, sessionKey) = options.FastPakeAuthClient.CreateAuth(options.Payload, options.EncryptPayload);
                }
                options.Payload = null;
                await cipher.CryptoStream.WriteSerializedAsync(auth, cancellationToken).DynamicContext();
                // Get the server response and create the context
                if (options.GetAuthenticationResponse)
                {
                    await cipher.DisposeAsync().DynamicContext();
                    cipher = null;
                    await stream.FlushAsync(cancellationToken).DynamicContext();
                    AuthSequences sequence = (AuthSequences)await stream.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                    switch (sequence)
                    {
                        case AuthSequences.Authentication:
                            break;
                        case AuthSequences.Error:
                            throw new UnauthorizedAccessException("The server denied the authentication");
                        default:
                            throw new InvalidDataException($"Invalid server response sequence {sequence}");
                    }
                }
                return new(options, cryptoOptions.Password.ExtendKey(sessionKey));
            }
            finally
            {
                if (cipher is not null) await cipher.DisposeAsync().DynamicContext();
                symmetricKey?.Dispose();
                serverRandom?.Clear();
                sessionKey?.Clear();
                auth?.Dispose();
                cryptoOptions?.Clear();
                options.Dispose();
            }
        }

        /// <summary>
        /// Authentication payload
        /// </summary>
        public sealed class AuthPayload : StreamSerializerBase
        {
            /// <summary>
            /// Object version
            /// </summary>
            public const int VERSION = 1;

            /// <summary>
            /// Constructor
            /// </summary>
            public AuthPayload() : base(VERSION) { }

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="payload">Payload</param>
            internal AuthPayload(in byte[]? payload) : this() => Payload = payload;

            /// <summary>
            /// Created time (UTC)
            /// </summary>
            public DateTime Created { get; private set; } = DateTime.UtcNow;

            /// <summary>
            /// Payload
            /// </summary>
            [CountLimit(short.MaxValue)]
            [SensitiveData]
            public byte[]? Payload { get; private set; }

            /// <inheritdoc/>
            protected override void Serialize(Stream stream)
            {
                stream.Write(Created.Ticks)
                    .WriteBytesNullable(Payload);
            }

            /// <inheritdoc/>
            protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
            {
                await stream.WriteAsync(Created.Ticks, cancellationToken).DynamicContext();
                await stream.WriteBytesNullableAsync(Payload, cancellationToken).DynamicContext();
            }

            /// <inheritdoc/>
            protected override void Deserialize(Stream stream, int version)
            {
                Created = new(stream.ReadLong(version), DateTimeKind.Utc);
                Payload = stream.ReadBytesNullable(version, minLen: 1, maxLen: short.MaxValue)?.Value;
            }

            /// <inheritdoc/>
            protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
            {
                Created = new(await stream.ReadLongAsync(version, cancellationToken: cancellationToken).DynamicContext(), DateTimeKind.Utc);
                Payload = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
            }

            /// <summary>
            /// Cast as serialized data
            /// </summary>
            /// <param name="payload">Payload</param>
            public static implicit operator byte[](in AuthPayload payload) => payload.ToBytes();

            /// <summary>
            /// Cast from serialized data
            /// </summary>
            /// <param name="data">Serialized data</param>
            public static implicit operator AuthPayload(in byte[] data) => data.ToObject<AuthPayload>();
        }
    }
}
