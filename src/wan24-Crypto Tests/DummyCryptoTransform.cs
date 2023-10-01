using System.Security.Cryptography;

namespace wan24_Crypto_Tests
{
    public sealed class DummyCryptoTransform : ICryptoTransform
    {
        public DummyCryptoTransform() { }

        public bool CanReuseTransform => true;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => 1;

        public int OutputBlockSize => 1;

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            inputBuffer.AsSpan(inputOffset, inputCount).CopyTo(outputBuffer.AsSpan(outputOffset));
            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount) => inputBuffer.AsSpan(inputOffset, inputCount).ToArray();

        public void Dispose() => GC.SuppressFinalize(this);
    }
}
