using Crypto.Bits;
using Crypto.Interfaces;

namespace Crypto.Des;


public sealed class DesRoundFunction : IRoundFunction
{
    public byte[] Transform(byte[] block, byte[] roundKey)
    {
        ArgumentNullException.ThrowIfNull(block);
        ArgumentNullException.ThrowIfNull(roundKey);

        if (block.Length != 4)
            throw new ArgumentException("Вход функции F DES - 32 бита (4 байта).", nameof(block));

        if (roundKey.Length != 6)
            throw new ArgumentException("Раундовый ключ DES - 48 бит (6 байт).", nameof(roundKey));

        byte[] expanded = BitPermutation.Permute(block, DesTables.Expansion, BitOrder.MsbFirst, 1);

        for (int i = 0; i < expanded.Length; i++)
        {
            expanded[i] ^= roundKey[i];
        }

        byte[] substituted = Substitute(expanded);

        return BitPermutation.Permute(substituted, DesTables.Permutation, BitOrder.MsbFirst, 1);
    }

    private static byte[] Substitute(byte[] input)
    {

        ulong bits = 0;
        foreach (byte b in input)
        {
            bits = (bits << 8) | b;
        }

        uint output = 0;

        for (int box = 0; box < 8; box++)
        {
            int six = (int)(bits >> (42 - 6 * box)) & 0x3F; 
            int row = ((six >> 4) & 0b10) | (six & 1);        
            int column = (six >> 1) & 0xF;                    

            output = (output << 4) | DesTables.SBoxes[box][row * 16 + column];
        }

        return [(byte)(output >> 24), (byte)(output >> 16), (byte)(output >> 8), (byte)output];
    }
}
