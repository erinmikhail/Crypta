using Crypto.Interfaces;

namespace Crypto.Modes;

/// <summary>
/// В 2 стороны исп только макса. Шифр - послед, дешифр - параллел.
/// Хранит сост — пред блок шифр.
/// </summary>
internal sealed class CfbMode : ICipherModeProcessor
{
    private readonly ISymmetricCipher _cipher;
    private readonly byte[] _previous;  

    public CfbMode(ISymmetricCipher cipher, byte[] iv)
    {
        _cipher = cipher;
        _previous = (byte[])iv.Clone();
    }

    public void Encrypt(byte[] buffer)
    {
        int blockSize = _cipher.BlockSize;

        for (int offset = 0; offset < buffer.Length; offset += blockSize)
        {
            byte[] keystream = _cipher.EncryptBlock(_previous);    
            Span<byte> block = buffer.AsSpan(offset, blockSize);   

            BlockUtils.XorInPlace(block, keystream);            
            block.CopyTo(_previous);                              
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

            byte[] previous = i == 0
                ? _previous                                              
                : source.AsSpan(offset - blockSize, blockSize).ToArray(); 

            byte[] keystream = _cipher.EncryptBlock(previous);           
            BlockUtils.XorInPlace(buffer.AsSpan(offset, blockSize), keystream); 
        });

        source.AsSpan(buffer.Length - blockSize, blockSize).CopyTo(_previous);
    }
}
