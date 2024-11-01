﻿using System.Buffers;
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
        public TimeoutToken(in Stream stream)
        {
            _Timeout = stream.ReadLong();
            _Payload = stream.ReadULong();
            _MAC = new byte[MacHmacSha384Algorithm.MAC_LENGTH];
            stream.ReadExactly(_MAC);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="data">Serialized data</param>
        public TimeoutToken(in ReadOnlySpan<byte> data)
        {
            if (data.Length < STRUCT_LENGTH) throw new ArgumentOutOfRangeException(nameof(data));
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
        private TimeoutToken(in long timeout, in ulong payload, in byte[] mac)
        {
            if (mac.Length != STRUCT_LENGTH) throw new ArgumentOutOfRangeException(nameof(mac));
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
        public TimeSpan TimeLeft
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
        public bool ValidateToken(in byte[] pwd, in bool throwOnError = true)
        {
            using RentedMemoryRef<byte> buffer = new(MAC_OFFSET, clean: false);
            Span<byte> bufferSpan = buffer.Span;
            _Timeout.GetBytes(bufferSpan);
            _Payload.GetBytes(bufferSpan[PAYLOAD_OFFSET..]);
            if (bufferSpan.Mac(pwd, MacHmacSha384Algorithm.Instance.DefaultOptions).SlowCompare(_MAC)) return true;
            if (!throwOnError) return false;
            throw new CryptographicException("MAC mismatch", new InvalidDataException());
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <returns>MAC</returns>
        public byte[] CreateMac(in byte[] pwd)
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
        public Span<byte> CreateMac(in byte[] pwd, in Span<byte> outputBuffer)
        {
            using RentedMemoryRef<byte> buffer = new(MAC_OFFSET, clean: false);
            Span<byte> bufferSpan = buffer.Span;
            _Timeout.GetBytes(bufferSpan);
            _Payload.GetBytes(bufferSpan[PAYLOAD_OFFSET..]);
            bufferSpan.Mac(pwd, outputBuffer, MacHmacSha384Algorithm.Instance.DefaultOptions);
            return outputBuffer;
        }

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="buffer">Buffer (if <see langword="null"/>, the returned serialized data needs to be disposed)</param>
        /// <param name="pool">Buffer pool</param>
        /// <returns>Serialized data</returns>
        public RentedMemory<byte> Serialize(in RentedMemory<byte>? buffer = null, in MemoryPool<byte>? pool = null)
        {
            RentedMemory<byte> res;
            if (buffer is not null)
            {
                if (buffer.Value.Memory.Length < STRUCT_LENGTH) throw new ArgumentOutOfRangeException(nameof(buffer));
                res = buffer.Value;
            }
            else
            {
                res = new(STRUCT_LENGTH, pool, clean: false)
                {
                    Clear = true
                };
            }
            Span<byte> resSpan = res.Memory.Span;
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
        public void Serialize(in Stream stream, in RentedMemory<byte>? buffer = null, MemoryPool<byte>? pool = null)
        {
            RentedMemory<byte> data = Serialize(buffer, pool);
            try
            {
                stream.Write(data.Memory.Span[..STRUCT_LENGTH]);
            }
            finally
            {
                if (!buffer.HasValue) data.Dispose();
            }
        }

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">Buffer</param>
        /// <param name="pool">Buffer pool</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async ValueTask SerializeAsync(Stream stream, RentedMemory<byte>? buffer = null, MemoryPool<byte>? pool = null, CancellationToken cancellationToken = default)
        {
            RentedMemory<byte> data = Serialize(buffer, pool);
            try
            {
                await stream.WriteAsync(data.Memory[..STRUCT_LENGTH], cancellationToken).DynamicContext();
            }
            finally
            {
                if (!buffer.HasValue) data.Dispose();
            }
        }

        /// <inheritdoc/>
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext) => ValidatableObjectBase.ObjectValidatable(this);

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
        public static explicit operator TimeoutToken?(byte[]? ttData) => ttData is null ? null : new(ttData);

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
