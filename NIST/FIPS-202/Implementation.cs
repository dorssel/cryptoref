using Dorssel.Security.Cryptography.Reference.FIPS_202.ExtensionMethods;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("UnitTests")]

namespace Dorssel.Security.Cryptography.Reference.FIPS_202;

public class KECCAK_p
{
    const int b = 1600;
    const int w = 64;
    const int l = 6;

    static char[,,] ConvertStringToStateArray(string S)
    {
        InputValidation.BitStringLength(S, b);

        var A = new char[5, 5, w];
        for (int x = 0; x < 5; ++x)
        {
            for (int y = 0; y < 5; ++y)
            {
                for (int z = 0; z < w; ++z)
                {
                    A[x, y, z] = S[w * (5 * y + x) + z];
                }
            }
        }
        return A;
    }

    static string ConvertStateArrayToString(char[,,] A)
    {
        InputValidation.StateMatrix(A, w);

        var Lane = new string[5, 5];
        for (int i = 0; i < 5; ++i)
        {
            for (int j = 0; j < 5; ++j)
            {
                Lane[i, j] = new(Enumerable.Range(0, w).Select((z) => A[i, j, z]).ToArray());
            }
        }

        var Plane = new string[5];
        for (int j = 0; j < 5; ++j)
        {
            Plane[j] = Lane[0, j] + Lane[1, j] + Lane[2, j] + Lane[3, j] + Lane[4, j];
        }

        var S = Plane[0] + Plane[1] + Plane[2] + Plane[3] + Plane[4];
        return S;
    }

    static char[,,] theta(char[,,] A)
    {
        InputValidation.StateMatrix(A, w);

        var C = new char[5, w];
        for (int x = 0; x < 5; ++x)
        {
            for (int z = 0; z < w; ++z)
            {
                C[x, z] = A[x, 0, z].Xor(A[x, 1, z]).Xor(A[x, 2, z]).Xor(A[x, 3, z]).Xor(A[x, 4, z]);
            }
        }

        var D = new char[5, w];
        for (int x = 0; x < 5; ++x)
        {
            for (int z = 0; z < w; ++z)
            {
                D[x, z] = C[(x - 1).Mod(5), z].Xor(C[(x + 1).Mod(5), (z - 1).Mod(w)]);
            }
        }

        var Aprime = new char[5, 5, w];
        for (int x = 0; x < 5; ++x)
        {
            for (int y = 0; y < 5; ++y)
            {
                for (int z = 0; z < w; ++z)
                {
                    Aprime[x, y, z] = A[x, y, z].Xor(D[x, z]);
                }
            }
        }
        return Aprime;
    }

    static char[,,] rho(char[,,] A)
    {
        InputValidation.StateMatrix(A, w);

        var Aprime = new char[5, 5, w];
        for (int z = 0; z < w; ++z)
        {
            Aprime[0, 0, z] = A[0, 0, z];
        }
        var (x, y) = (1, 0);
        for (int t = 0; t <= 23; ++t)
        {
            for (int z = 0; z < w; ++z)
            {
                Aprime[x, y, z] = A[x, y, (z - (t + 1) * (t + 2) / 2).Mod(w)];
            }
            (x, y) = (y, (2 * x + 3 * y).Mod(5));
        }
        return Aprime;
    }

    static char[,,] pi(char[,,] A)
    {
        InputValidation.StateMatrix(A, w);

        var Aprime = new char[5, 5, w];
        for (int x = 0; x < 5; ++x)
        {
            for (int y = 0; y < 5; ++y)
            {
                for (int z = 0; z < w; ++z)
                {
                    Aprime[x, y, z] = A[(x + 3 * y).Mod(5), x, z];
                }
            }
        }
        return Aprime;
    }

    static char[,,] chi(char[,,] A)
    {
        InputValidation.StateMatrix(A, w);

        var Aprime = new char[5, 5, w];
        for (int x = 0; x < 5; ++x)
        {
            for (int y = 0; y < 5; ++y)
            {
                for (int z = 0; z < w; ++z)
                {
                    Aprime[x, y, z] = A[x, y, z].Xor(((A[(x + 1).Mod(5), y, z].Xor('1')).Dot(A[(x + 2).Mod(5), y, z])));
                }
            }
        }
        return Aprime;
    }

    static char rc(int t)
    {
        if (t.Mod(255) == 0)
        {
            return '1';
        }
        var R = "10000000";
        for (int i = 0; i < t.Mod(255); ++i)
        {
            R = "0" + R;
            {
                var Rarray = R.ToCharArray();
                Rarray[0] = Rarray[0].Xor(Rarray[8]);
                Rarray[4] = Rarray[4].Xor(Rarray[8]);
                Rarray[5] = Rarray[5].Xor(Rarray[8]);
                Rarray[6] = Rarray[6].Xor(Rarray[8]);
                R = new(Rarray);
            }
            R = R[..8];
        }
        return R[0];
    }

    static char[,,] iota(char[,,] A, int ir)
    {
        InputValidation.StateMatrix(A, w);

        var Aprime = new char[5, 5, w];
        for (int x = 0; x < 5; ++x)
        {
            for (int y = 0; y < 5; ++y)
            {
                for (int z = 0; z < w; ++z)
                {
                    Aprime[x, y, z] = A[x, y, z];
                }
            }
        }
        var RC = new string('0', w);
        {
            var RCarray = RC.ToCharArray();
            for (int j = 0; j <= l; ++j)
            {
                RCarray[(1 << j) - 1] = rc(j + 7 * ir);
            }
            RC = new(RCarray);
        }
        for (int z = 0; z < w; ++z)
        {
            Aprime[0, 0, z] = Aprime[0, 0, z].Xor(RC[z]);
        }
        return Aprime;
    }

    static char[,,] Rnd(char[,,] A, int ir)
    {
        InputValidation.StateMatrix(A, w);
        InputValidation.NonNegative(ir);

        return iota(chi(pi(rho(theta(A)))), ir);
    }

    public Func<string, string> this[int b, int nr] => (string S) =>
    {
        var A = ConvertStringToStateArray(S);
        for (int ir = 12 + 2 * l - nr; ir <= 12 + 2 * l - 1; ++ir)
        {
            A = Rnd(A, ir);
        }
        var Sprime = ConvertStateArrayToString(A);
        return Sprime;
    };
}

public class SPONGE
{
    const int b = 1600;

    public Func<string, int, string> this[Func<string, string> f, Func<int, int, string> pad, int r] => (string N, int d) =>
    {
        var P = N + pad(r, N.Length);
        var n = P.Length / r;
        var c = b - r;
        var P_ = P.Chunk(r).Select(c => new string(c)).ToArray();
        var S = new string('0', b);
        for (int i = 0; i <= n - 1; ++i)
        {
            S = f(S.Xor(P_[i] + new string('0', c)));
        }
        var Z = "";
        do
        {
            Z = Z + S[..r];
            // FIXME: notation is '|Z|', but that notation is not defined in Section 2.3; interpreted as 'len(Z)'
            if (d <= Z.Length)
            {
                return Z[..d];
            }
            S = f(S);
        } while (true);
    };
}


public class KECCAK
{
    static readonly KECCAK_p KECCAK_p = new();
    static readonly SPONGE SPONGE = new();

    static string pad10_1(int x, int m)
    {
        var j = (-m - 2).Mod(x);
        var P = "1" + new string('0', j) + "1";
        return P;
    }

    public Func<string, int, string> this[int c] => SPONGE[KECCAK_p[1600, 24], pad10_1, 1600 - c];
}

public class SHA3
{
    static readonly KECCAK KECCAK = new();

    public static string SHA3_224(string M) => KECCAK[448](M + "01", 224);
    public static string SHA3_256(string M) => KECCAK[512](M + "01", 256);
    public static string SHA3_384(string M) => KECCAK[768](M + "01", 384);
    public static string SHA3_512(string M) => KECCAK[1024](M + "01", 512);

    public static string SHAKE128(string M, int d) => KECCAK[256](M + "1111", d);
    public static string SHAKE256(string M, int d) => KECCAK[512](M + "1111", d);
}
