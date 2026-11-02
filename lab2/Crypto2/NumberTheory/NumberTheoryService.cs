using System.Numerics;
using System.Reflection.Emit;

namespace Crypto2.NumberTheory;

public sealed class NumberTheoryService
{
    public BigInteger Gcd(BigInteger a, BigInteger b)
    {
        a = Abs(a);
        b = Abs(b);

        while (!b.IsZero)
        {
            BigInteger r = a % b;
            a = b;
            b = r;
        }

        return a;
    }

    private static BigInteger Abs(BigInteger x) => x.Sign < 0 ? -x : x;
}