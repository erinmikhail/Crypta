using Crypto.Interfaces;

namespace Crypto.Modes;

/// <summary>
/// Шифр - последовательно, дешифрование - параллельно.
/// Хранит состояние — предыдущий блок шифртекста.
/// </summary>
internal sealed class CbcMode : ICipherModeProcessor
{
    private readonly ISymmetricCipher _cipher;
    private readonly byte[] _previous; 

    public CbcMode(ISymmetricCipher cipher, byte[] iv)
    {
        _cipher = cipher;
        _previous = (byte[])iv.Clone();
    }

    public void Encrypt(byte[] buffer)
    {
        int blockSize = _cipher.BlockSize;

        for (int offset = 0; offset < buffer.Length; offset += blockSize)
        {
            byte[] block = buffer.AsSpan(offset, blockSize).ToArray();  

            BlockUtils.XorInPlace(block, _previous);                 
            byte[] encrypted = _cipher.EncryptBlock(block);             

            encrypted.CopyTo(buffer, offset);                           
            encrypted.CopyTo(_previous, 0);                             
        }
    }

    public void Decrypt(byte[] buffer)
    {
        int blockSize = _cipher.BlockSize;
        int blockCount = buffer.Length / blockSize;

        if (blockCount == 0)
            return;


        byte[] source = (byte[])buffer.Clone();

        BlockUtils.ForEachBlock(blockCount, i =>
        {
            int offset = i * blockSize;

            byte[] decrypted = _cipher.DecryptBlock(source.AsSpan(offset, blockSize).ToArray()); 

            ReadOnlySpan<byte> previous = i == 0
                ? _previous.AsSpan()
                : source.AsSpan(offset - blockSize, blockSize);    

            BlockUtils.XorInPlace(decrypted, previous);         
            decrypted.CopyTo(buffer, offset);
        });

        // Сост для след вызова - ласт блок шифртекста
        source.AsSpan(buffer.Length - blockSize, blockSize).CopyTo(_previous);
    }
}
