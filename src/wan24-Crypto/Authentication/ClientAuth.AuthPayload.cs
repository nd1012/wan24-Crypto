using System.Diagnostics.CodeAnalysis;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
{
    // Authentication payload
    public static partial class ClientAuth
    {
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
            /// <param name="publicKeyId">ID of the public key (<see langword="null"/> during authentication, only required for the signup)</param>
            /// <param name="publickeys">Public keys (only during signup)</param>
            /// <param name="ksr">Key signing request (only during signup)</param>
            public AuthPayload(in byte[]? payload, in byte[]? publicKeyId = null, in PublicKeySuite? publickeys = null, in AsymmetricPublicKeySigningRequest? ksr = null) : this()
            {
                Payload = payload;
                PublicKeyId = publicKeyId;
                PublicKeys = publickeys;
                KeySigningRequest = ksr;
            }

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

            /// <summary>
            /// ID of the public key (<see langword="null"/> during authentication, only required for the signup)
            /// </summary>
            [CountLimit(HashSha512Algorithm.HASH_LENGTH)]
            public byte[]? PublicKeyId { get; private set; }

            /// <summary>
            /// Public keys (only during signup)
            /// </summary>
            [RequiredIf(nameof(KeySigningRequest))]
            public PublicKeySuite? PublicKeys { get; private set; }

            /// <summary>
            /// Key signing request (only during signup)
            /// </summary>
            public AsymmetricPublicKeySigningRequest? KeySigningRequest { get; private set; }

            /// <summary>
            /// Is a new client? (may still be an existing client which wants to update his public keys, if the PAKE authentication exists and is valid!)
            /// </summary>
            [MemberNotNullWhen(returnValue: true, nameof(PublicKeyId))]
            [MemberNotNullWhen(returnValue: true, nameof(PublicKeys))]
            public bool IsNewClient => PublicKeyId is not null && PublicKeys is not null;

            /// <summary>
            /// Is a temporary client?
            /// </summary>
            public bool IsTemporaryClient => IsNewClient && PublicKeys.SignedPublicKey is null && KeySigningRequest is null;

            /// <summary>
            /// Is an existing client?
            /// </summary>
            [MemberNotNullWhen(returnValue: true, nameof(PublicKeyId))]
            public bool IsExistingClient => PublicKeyId is not null && PublicKeys is null;

            /// <inheritdoc/>
            protected override void Serialize(Stream stream)
            {
                stream.Write(Created.Ticks)
                    .WriteBytesNullable(Payload)
                    .WriteBytesNullable(PublicKeyId);
                if (PublicKeyId is null) return;
                stream.WriteSerializedNullable(PublicKeys)
                    .WriteSerializedNullable(KeySigningRequest);
            }

            /// <inheritdoc/>
            protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
            {
                await stream.WriteAsync(Created.Ticks, cancellationToken).DynamicContext();
                await stream.WriteBytesNullableAsync(Payload, cancellationToken).DynamicContext();
                await stream.WriteBytesNullableAsync(PublicKeyId, cancellationToken).DynamicContext();
                if (PublicKeyId is null) return;
                await stream.WriteSerializedNullableAsync(PublicKeys, cancellationToken).DynamicContext();
                await stream.WriteSerializedNullableAsync(KeySigningRequest, cancellationToken).DynamicContext();
            }

            /// <inheritdoc/>
            protected override void Deserialize(Stream stream, int version)
            {
                Created = new(stream.ReadLong(version), DateTimeKind.Utc);
                Payload = stream.ReadBytesNullable(version, minLen: 1, maxLen: short.MaxValue)?.Value;
                PublicKeyId = stream.ReadBytesNullable(version, minLen: 1, maxLen: short.MaxValue)?.Value;
                if (PublicKeyId is null) return;
                PublicKeys = stream.ReadSerializedNullable<PublicKeySuite>(version);
                KeySigningRequest = stream.ReadSerializedNullable<AsymmetricPublicKeySigningRequest>(version);
            }

            /// <inheritdoc/>
            protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
            {
                Created = new(await stream.ReadLongAsync(version, cancellationToken: cancellationToken).DynamicContext(), DateTimeKind.Utc);
                Payload = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
                PublicKeyId = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
                if (PublicKeyId is null) return;
                PublicKeys = await stream.ReadSerializedNullableAsync<PublicKeySuite>(version, cancellationToken).DynamicContext();
                KeySigningRequest = await stream.ReadSerializedNullableAsync<AsymmetricPublicKeySigningRequest>(version, cancellationToken).DynamicContext();
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
