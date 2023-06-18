using System.Buffers;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Timeout token
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public readonly record struct TimeoutToken : IObjectValidatable
    {
        /// <summary>
        /// Structure length in bytes
        /// </summary>
        public const int STRUCT_LENGTH = MAC_OFFSET + MacHmacSha384Algorithm.MAC_LENGTH;
        /// <summary>
        /// Timeout byte offset
        /// </summary>
        public const int TIMEOUT_OFFSET = 0;
        /// <summary>
        /// Payload byte offset
        /// </summary>
        public const int PAYLOAD_OFFSET = sizeof(long);
        /// <summary>
        /// MAC byte offset
        /// </summary>
        public const int MAC_OFFSET = PAYLOAD_OFFSET + sizeof(ulong);

        /// <summary>
        /// Timeout ticks (UTC)
        /// </summary>
        [FieldOffset(TIMEOUT_OFFSET)]
        private readonly long _Timeout;
        /// <summary>
        /// Payload
        /// </summary>
        [FieldOffset(PAYLOAD_OFFSET)]
        private readonly ulong _Payload;
        /// <summary>
        /// MAC
        /// </summary>
        [FieldOffset(MAC_OFFSET), MarshalAs(UnmanagedType.ByValArray, SizeConst = MacHmacSha384Algorithm.MAC_LENGTH)]
        private readonly byte[] _MAC;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="validFrom">Valid from (UTC)</param>
        /// <param name="timeout">Timeout</param>
        /// <param name="payload">Payload</param>
        /// <param name="pwd">Password</param>
        public TimeoutToken(in DateTime validFrom, in TimeSpan timeout, in ulong payload, in byte[] pwd)
        {
            _Timeout = (validFrom.ToUniversalTime() + timeout).Ticks;
            _Payload = payload;
            _MAC = new byte[MacHmacSha384Algorithm.MAC_LENGTH];
            CreateMac(pwd, _MAC.AsSpan());
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="timeout">Valid until (UTC; excluding)</param>
        /// <param name="payload">Payload</param>
        /// <param name="pwd">Password</param>
        public TimeoutToken(in DateTime timeout, in ulong payload, in byte[] pwd)
        {
            _Timeout = timeout.ToUniversalTime().Ticks;
            _Payload = payload;
            _MAC = new byte[MacHmacSha384Algorithm.MAC_LENGTH];
            CreateMac(pwd, _MAC.AsSpan());
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="stream">Stream</param>
        public TimeoutToken(Stream stream)
        {
            _Timeout = stream.ReadLong();
            _Payload = stream.ReadULong();
            _MAC = new byte[MacHmacSha384Algorithm.MAC_LENGTH];
            int red = stream.Read(_MAC);
            if (red != _MAC.Length) throw new IOException($"Failed to read the MAC bytes (expected {STRUCT_LENGTH} bytes, red only {red} bytes)");
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="data">Serialized data</param>
        public TimeoutToken(in ReadOnlySpan<byte> data)
        {
            ArgumentValidationHelper.EnsureValidArgument(nameof(data), STRUCT_LENGTH, int.MaxValue, data.Length, "Not enough data");
            _Timeout = data.ToLong();
            _Payload = data[PAYLOAD_OFFSET..].ToULong();
            _MAC = data.Slice(MAC_OFFSET, MacHmacSha384Algorithm.MAC_LENGTH).ToArray();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="timeout">Timeout ticks (UTC)</param>
        /// <param name="payload">Payload</param>
        /// <param name="mac">MAC (won't be copied!)</param>
        private TimeoutToken(long timeout, ulong payload, byte[] mac)
        {
            ArgumentValidationHelper.EnsureValidArgument(
                nameof(mac), 
                STRUCT_LENGTH, 
                STRUCT_LENGTH, 
                mac.Length, 
                $"Invalid MAC length (expected {MacHmacSha384Algorithm.MAC_LENGTH} bytes, got {mac.Length} bytes)"
                );
            _Timeout = timeout;
            _Payload = payload;
            _MAC = mac;
        }

        /// <summary>
        /// Timeout (UTC)
        /// </summary>
        public DateTime Timeout => new(_Timeout, DateTimeKind.Utc);

        /// <summary>
        /// Payload
        /// </summary>
        public ulong Payload => _Payload;

        /// <summary>
        /// MAC
        /// </summary>
        [Range(MacHmacSha384Algorithm.MAC_LENGTH, MacHmacSha384Algorithm.MAC_LENGTH)]
        public ReadOnlyCollection<byte> MAC => new(_MAC);

        /// <summary>
        /// Is timeout? (if <see langword="true"/>, the current time exceeds the timeout and the token is invalid)
        /// </summary>
        public bool IsTimeout => DateTime.UtcNow.Ticks >= _Timeout;

        /// <summary>
        /// Time left until timeout
        /// </summary>
        public TimeSpan Timeleft
        {
            get
            {
                long ticks = DateTime.UtcNow.Ticks;
                return ticks >= _Timeout ? TimeSpan.Zero : TimeSpan.FromTicks(_Timeout - ticks);
            }
        }

        /// <summary>
        /// Validate the token integrity (NOT the timeout!)
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <returns>If the token integrity is valid</returns>
        /// <exception cref="CryptographicException">The token integrity is invalid (the token may have been manipulated)</exception>
        public bool ValidateToken(in byte[] pwd, bool throwOnError = true)
        {
            using RentedArray<byte> buffer = new(MAC_OFFSET, clean: false);
            _Timeout.GetBytes(buffer.Span);
            _Payload.GetBytes(buffer.Span[PAYLOAD_OFFSET..]);
            if (buffer.Span.Mac(pwd, MacHmacSha384Algorithm.Instance.DefaultOptions).SlowCompare(_MAC)) return true;
            if (throwOnError) throw new CryptographicException("MAC mismatch", new InvalidDataException());
            return false;
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <returns>MAC</returns>
        public byte[] CreateMac(byte[] pwd)
        {
            byte[] res = new byte[MacHmacSha384Algorithm.MAC_LENGTH];
            CreateMac(pwd, res);
            return res;
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <returns>MAC</returns>
        public Span<byte> CreateMac(byte[] pwd, in Span<byte> outputBuffer)
        {
            using RentedArray<byte> buffer = new(MAC_OFFSET, clean: false);
            _Timeout.GetBytes(buffer.Span);
            _Payload.GetBytes(buffer.Span[PAYLOAD_OFFSET..]);
            return buffer.Span.Mac(pwd, outputBuffer, MacHmacSha384Algorithm.Instance.DefaultOptions);
        }

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <param name="pool">Buffer pool (if given, and <c>buffer</c> is <see langword="null"/>, the returned serialized data needs to be returned to this pool)</param>
        /// <returns>Serialized data</returns>
        public byte[] Serialize(byte[]? buffer = null, ArrayPool<byte>? pool = null)
        {
            byte[] res;
            if (buffer != null)
            {
                if (buffer.Length < STRUCT_LENGTH) throw new ArgumentOutOfRangeException(nameof(buffer));
                res = buffer;
            }
            else if (pool != null)
            {
                res = pool.Rent(STRUCT_LENGTH);
            }
            else
            {
                res = new byte[STRUCT_LENGTH];
            }
            Span<byte> resSpan = res.AsSpan();
            _Timeout.GetBytes(resSpan);
            _Payload.GetBytes(resSpan[PAYLOAD_OFFSET..]);
            _MAC.AsSpan().CopyTo(resSpan[MAC_OFFSET..]);
            return res;
        }

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">Buffer</param>
        /// <param name="pool">Buffer pool</param>
        public void Serialize(Stream stream, byte[]? buffer = null, ArrayPool<byte>? pool = null)
        {
            if (buffer == null) pool ??= ArrayPool<byte>.Shared;
            byte[] data = Serialize(buffer, pool);
            try
            {
                stream.Write(data.AsSpan(0, STRUCT_LENGTH));
            }
            finally
            {
                if (buffer == null) pool!.Return(data);
            }
        }

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">Buffer</param>
        /// <param name="pool">Buffer pool</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async ValueTask SerializeAsync(Stream stream, byte[]? buffer = null, ArrayPool<byte>? pool = null, CancellationToken cancellationToken = default)
        {
            if (buffer == null) pool ??= ArrayPool<byte>.Shared;
            byte[] data = Serialize(buffer, pool);
            try
            {
                await stream.WriteAsync(data.AsMemory(0, STRUCT_LENGTH), cancellationToken).DynamicContext();
            }
            finally
            {
                if (buffer == null) pool!.Return(data);
            }
        }

        /// <inheritdoc/>
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext) => ValidatableObjectBase.ObjectValidatable(this);

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="tt">Timeout tokenn</param>
        public static implicit operator byte[](in TimeoutToken tt) => tt.Serialize();

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="tt">Timeout token</param>
        [return: NotNullIfNotNull(nameof(tt))]
        public static implicit operator byte[]?(in TimeoutToken? tt) => tt?.Serialize();

        /// <summary>
        /// Cast as timeout ticks (UTC)
        /// </summary>
        /// <param name="tt">Timeout token</param>
        public static implicit operator long(in TimeoutToken tt) => tt._Timeout;

        /// <summary>
        /// Cast as timeout (UTC)
        /// </summary>
        /// <param name="tt">Timeout token</param>
        public static implicit operator DateTime(in TimeoutToken tt) => tt.Timeout;

        /// <summary>
        /// Cast as payload
        /// </summary>
        /// <param name="tt">Timeout token</param>
        public static implicit operator ulong(in TimeoutToken tt) => tt._Payload;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="ttData">Timeout token data</param>
        public static explicit operator TimeoutToken(byte[] ttData) => new(ttData);

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="ttData">Timeout token data</param>
        public static explicit operator TimeoutToken(in Span<byte> ttData) => new(ttData);

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="ttData">Timeout token data</param>
        public static explicit operator TimeoutToken(in ReadOnlySpan<byte> ttData) => new(ttData);

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="ttData">Timeout token data</param>
        [return: NotNullIfNotNull(nameof(ttData))]
        public static explicit operator TimeoutToken?(byte[]? ttData) => ttData == null ? null : new(ttData);

        /// <summary>
        /// Create a timeout token from a serialized stream
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Timeout token</returns>
        public static async Task<TimeoutToken> DeserializeAsync(Stream stream, CancellationToken cancellationToken = default)
            => new(
                await stream.ReadLongAsync(cancellationToken: cancellationToken).DynamicContext(),
                await stream.ReadULongAsync(cancellationToken: cancellationToken).DynamicContext(),
                await stream.ReadFixedArrayAsync(new byte[MacHmacSha384Algorithm.MAC_LENGTH], cancellationToken: cancellationToken).DynamicContext()
                );
    }
}
