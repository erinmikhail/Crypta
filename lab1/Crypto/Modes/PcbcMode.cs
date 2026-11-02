using Crypto.Interfaces;

namespace Crypto.Modes;

///<summary>режим шифрования PCBC</summary>
internal sealed class PcbcMode : ICipherModeProcessor
{
    private readonly ISymmetricCipher _cipher;
    private readonly byte[] _feedback;

    public PcbcMode(ISymmetricCipher cipher, byte[] iv)
    {
        _cipher = cipher;
        _feedback = (byte[])iv.Clone();
    }

    public void Encrypt(byte[] buffer)
    {
        int blockSize = _cipher.BlockSize;

        for (int offset = 0; offset < buffer.Length; offset += blockSize)
        {
            byte[] plain = buffer.AsSpan(offset, blockSize).ToArray();

            byte[] input = (byte[])plain.Clone();
            BlockUtils.XorInPlace(input, _feedback);
            byte[] encrypted = _cipher.EncryptBlock(input);

            encrypted.CopyTo(buffer, offset);
            UpdateFeedback(plain, encrypted);
        }
    }

    public void Decrypt(byte[] buffer)
    {
        int blockSize = _cipher.BlockSize;

        for (int offset = 0; offset < buffer.Length; offset += blockSize)
        {
            byte[] cipherBlock = buffer.AsSpan(offset, blockSize).ToArray();

            byte[] plain = _cipher.DecryptBlock(cipherBlock);
            BlockUtils.XorInPlace(plain, _feedback);

            plain.CopyTo(buffer, offset);
            UpdateFeedback(plain, cipherBlock);
        }
    }

    private void UpdateFeedback(byte[] plain, byte[] cipherBlock)
    {
        plain.CopyTo(_feedback, 0);
        BlockUtils.XorInPlace(_feedback, cipherBlock);
    }
}