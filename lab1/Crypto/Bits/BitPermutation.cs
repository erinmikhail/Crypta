using System.Runtime.CompilerServices;

namespace Crypto.Bits;

///<summary>перестановка битов по правилу P-блока / i-й бит рез = бит входа с номером p[i] / ltn res в битах = len p-блока</summary>

public static class BitPermutation
{
    /// <param name="value">Значение для перестановки.</param>
    /// <param name="pBlock">Правило перестановки: номера битов входа для каждой позиции выхода.</param>
    /// <param name="bitOrder">Направление нумерации битов.</param>
    /// <param name="startIndex">Номер начального бита: 0 или 1.</param>
    /// <returns>Новый массив байтов с переставл битами.</returns>
    public static byte[] Permute(byte[] value, int[] pBlock, BitOrder bitOrder, int startIndex)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(pBlock);

        if (startIndex != 0 && startIndex != 1)
            throw new ArgumentOutOfRangeException(nameof(startIndex), "startIndex must be 0 or 1.");

        if (pBlock.Length == 0)
            throw new ArgumentException("pBlock cannot be empty.", nameof(pBlock));

        int inputBits = value.Length * 8;
        byte[] result = new byte[(pBlock.Length + 7) / 8];
        int outputBits = result.Length * 8;

        for (int j = 0; j < pBlock.Length; j++)
        {
            int sourceIndex = pBlock[j];

            if (sourceIndex < startIndex || sourceIndex > inputBits - 1 + startIndex)
                throw new ArgumentOutOfRangeException(nameof(pBlock), $"pBlock[{j}] = {sourceIndex} вне диапазона [{startIndex}; {inputBits - 1 + startIndex}].");

            int src = ToCanonical(sourceIndex, inputBits, bitOrder, startIndex);

            if (GetBit(value, src) == 1)
            {
                int dst = ToCanonical(j + startIndex, outputBits, bitOrder, startIndex);
                SetBit(result, dst);
            }
        }

        return result;
    }

    /// <summary>
    /// Переводит номер бита из заданной нумерации в канонич:
    /// от старш бита, начиная с 0.</summary>

    private static int ToCanonical(int index, int totalBits, BitOrder bitOrder, int startIndex)
    {
        int zeroBased = index - startIndex;

        return bitOrder == BitOrder.MsbFirst ? zeroBased : totalBits - 1 - zeroBased;
    }

    ///<summary> Чит бит по канонич позиц (0 = старш бит байта 0)</summary>
    private static int GetBit(byte[] bytes, int canonicalIndex)
    {
        int byteIndex = canonicalIndex / 8;
        int bitInByte = 7 - (canonicalIndex % 8);

        return (bytes[byteIndex] >> bitInByte) & 1;
    }

    /// <summary>Уст в 1 бит по канонич позиции.</summary>
    private static void SetBit(byte[] bytes, int canonicalIndex)
    {
        int byteIndex = canonicalIndex / 8;
        int bitInByte = 7 - (canonicalIndex % 8);

        bytes[byteIndex] |= (byte)(1 << bitInByte);
    }
}