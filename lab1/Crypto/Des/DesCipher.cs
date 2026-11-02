using Crypto.Bits;
using Crypto.Feistel;
using Crypto.Interfaces;

namespace Crypto.Des;


public sealed class DesCipher : ISymmetricCipher
{
    public const int KeySize = DesKeyExpansion.KeySize;

    private readonly FeistelNetwork _network =
        new(new DesKeyExpansion(), new DesRoundFunction(), blockSize: 8);

    public int BlockSize => 8;

    public void SetKey(byte[] key) => _network.SetKey(key);

    public byte[] EncryptBlock(byte[] block)
    {
        ValidateBlock(block);

        byte[] permuted = BitPermutation.Permute(block, DesTables.InitialPermutation, BitOrder.MsbFirst, 1);
        byte[] processed = _network.EncryptBlock(permuted);
        return BitPermutation.Permute(processed, DesTables.FinalPermutation, BitOrder.MsbFirst, 1);
    }

    public byte[] DecryptBlock(byte[] block)
    {
        ValidateBlock(block);

        byte[] permuted = BitPermutation.Permute(block, DesTables.InitialPermutation, BitOrder.MsbFirst, 1);
        byte[] processed = _network.DecryptBlock(permuted);
        return BitPermutation.Permute(processed, DesTables.FinalPermutation, BitOrder.MsbFirst, 1);
    }

    private void ValidateBlock(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);

        if (block.Length != BlockSize)
            throw new ArgumentException($"Блок DES должен быть длиной {BlockSize} байт.", nameof(block));
    }
}
