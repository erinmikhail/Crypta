using Crypto.Interfaces;

namespace Crypto.Modes;

/// <summary>
/// Блоки независимы, состояния нет - шифрование и дешифрование распараллеливаются.
/// </summary>
internal sealed class EcbMode : ICipherModeProcessor
{
    private readonly ISymmetricCipher _cipher;

    public EcbMode(ISymmetricCipher cipher)
    {
        _cipher = cipher;
    }

    public void Encrypt(byte[] buffer) => Process(buffer, encrypt: true);

    public void Decrypt(byte[] buffer) => Process(buffer, encrypt: false);

    private void Process(byte[] buffer, bool encrypt)
    {
        int blockSize = _cipher.BlockSize;
        int blockCount = buffer.Length / blockSize;

        BlockUtils.ForEachBlock(blockCount, i =>
        {
            int offset = i * blockSize;
            byte[] block = buffer.AsSpan(offset, blockSize).ToArray();

            byte[] result = encrypt
                ? _cipher.EncryptBlock(block)
                : _cipher.DecryptBlock(block);

            result.CopyTo(buffer, offset);
        });
    }
}
