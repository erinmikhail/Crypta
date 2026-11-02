using Crypto.Interfaces;

namespace Crypto.Modes;

///<summary>шифр и дешифр - тоже самое, по предыд маске</summary>
internal sealed class OfbMode : ICipherModeProcessor
{
    private readonly ISymmetricCipher _cipher;
    private readonly byte[] _register; //копия пред маски

    public OfbMode(ISymmetricCipher cipher, byte[] iv)
    {
        _cipher = cipher;
        _register = (byte[])iv.Clone();
    }

    public void Encrypt(byte[] buffer) => ApplyKeystream(buffer);
    public void Decrypt(byte[] buffer) => ApplyKeystream(buffer);
    private void ApplyKeystream(byte[] buffer)
    {
        int blockSize = _cipher.BlockSize;

        for (int offset = 0; offset < buffer.Length; offset += blockSize)
        {
            byte[] keystream = _cipher.EncryptBlock(_register);
            keystream.CopyTo(_register, 0);
            BlockUtils.XorInPlace(buffer.AsSpan(offset, blockSize), keystream);
        }
    }
}