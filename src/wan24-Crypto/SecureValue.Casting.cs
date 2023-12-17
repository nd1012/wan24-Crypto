using wan24.Core;

namespace wan24.Crypto
{
    // Casting
    public partial class SecureValue
    {
        /// <summary>
        /// Cast as value (should be cleared!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator byte[](in SecureValue value) => value.Value;

        /// <summary>
        /// Cast as value (should be cleaned!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator Span<byte>(in SecureValue value) => value.Value;

        /// <summary>
        /// Cast as value (should be cleaned!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator Memory<byte>(in SecureValue value) => value.Value;

        /// <summary>
        /// Cast as value (should be disposed!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator SecureByteArray(in SecureValue value) => new(value.Value);

        /// <summary>
        /// Cast as value (should be disposed!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator SecureByteArrayStruct(in SecureValue value) => new(value.Value);

        /// <summary>
        /// Cast as value (should be disposed!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator SecureByteArrayStructSimple(in SecureValue value) => new(value.Value);

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be cleared!)</param>
        public static implicit operator SecureValue(in byte[] value) => new(value);

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be copied)</param>
        public static implicit operator SecureValue(in SecureByteArray value) => new(value.Array.CloneArray());

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be copied)</param>
        public static implicit operator SecureValue(in SecureByteArrayStruct value) => new(value.Array.CloneArray());

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be copied)</param>
        public static implicit operator SecureValue(in ReadOnlySpan<byte> value) => new(value.ToArray());

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be copied)</param>
        public static implicit operator SecureValue(in ReadOnlyMemory<byte> value) => new(value.Span.ToArray());
    }
}
