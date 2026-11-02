namespace Crypto.Modes;

///<summary>вспом опер над блоками для разн режим шифр</summary>
internal static class BlockUtils
{
    public static void XorInPlace(Span<byte> target, ReadOnlySpan<byte> source)
    {
        if (target.Length != source.Length)
        {
            throw new ArgumentException("Длины блоков должны совпадать.");
        }

        for (int i = 0; i < target.Length; i++)
        {
            target[i] ^= source[i];
        }
    }

    public static void AddInPlace(Span<byte> target, ReadOnlySpan<byte> addend)
    {
        if (target.Length != addend.Length)
        {
            throw new ArgumentException("длины должн совпадать");
        }

        int carry = 0;

        for (int i = target.Length - 1; i >= 0; i--)
        {
            int sum = target[i] + addend[i] + carry;
            target[i] = (byte)sum;
            carry = sum >> 8;
        }
    }

    /// <summary>
    /// Мин число блоков, начиная с которого обработка распараллеливается.
    /// </summary>
    public const int ParallelThreshold = 1024;

    /// <summary>параллел на всех ядрах, если блоков не меньше ParallelThreshold, иначе по очереди</summary>
    public static void ForEachBlock(int blockCount, Action<int> body)
    {
        if (blockCount >= ParallelThreshold)
        {
            Parallel.For(0, blockCount, body);
        }
        else
        {
            for (int i = 0; i < blockCount; i++)
            {
                body(i);
            }
        }
    }
}
