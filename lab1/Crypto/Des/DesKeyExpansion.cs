using Crypto.Bits;
using Crypto.Interfaces;

namespace Crypto.Des;


public sealed class DesKeyExpansion : IKeyExpansion
{
    ///<summary>Длина ключа DES в байтах (64 бита, из них 56 значимых).</summary>
    public const int KeySize = 8;

    private static readonly int[] RotateBy1 = BuildRotation(1);
    private static readonly int[] RotateBy2 = BuildRotation(2);

    public byte[][] GenerateRoundKeys(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeySize)
            throw new ArgumentException($"Ключ DES должен быть длиной {KeySize} байт.", nameof(key));

        byte[] cd = BitPermutation.Permute(key, DesTables.PermutedChoice1, BitOrder.MsbFirst, 1);

        byte[][] roundKeys = new byte[DesTables.Shifts.Length][];

        for (int round = 0; round < roundKeys.Length; round++)
        {

            int[] rotation = DesTables.Shifts[round] == 1 ? RotateBy1 : RotateBy2;
            cd = BitPermutation.Permute(cd, rotation, BitOrder.MsbFirst, 1);


            roundKeys[round] = BitPermutation.Permute(cd, DesTables.PermutedChoice2, BitOrder.MsbFirst, 1);
        }

        return roundKeys;
    }


    private static int[] BuildRotation(int shift)
    {
        int[] table = new int[56];

        for (int j = 0; j < 28; j++)
        {
            table[j] = (j + shift) % 28 + 1;           
            table[28 + j] = 28 + (j + shift) % 28 + 1; 
        }

        return table;
    }
}
