using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int x(int phi_n, int e, int x = 0)
        {
            double vers = 1.0; int i = 0;
            for (; ; )
            {
                if (!(i >= e))
                {
                    double wx = i * phi_n;
                    vers = wx;
                    vers -= -1;
                    vers /= e;
                    int xe = 0;
                    if (vers % 1 == xe)
                    {
                        break;
                    }

                    i++;
                }
                else
                {
                    break;
                }
            }
            return (int)vers;
        }
        public int _POWMOD(int n1, int n2, int M, float f = 0)
        {
            int p = 1, i = 0;
            for (; ; )
            {
                if (i < n2)
                {
                    p *= n1;
                    p %= M;
                    i++;
                }
                else
                {
                    break;
                }

            }
            return p;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int x = p * q, C;
            C = _POWMOD(M, e, x);
            return C;
        }
        public int Decrypt(int p, int q, int C, int e)
        {
            int[] arr = new int[4];
            arr[0] = p * q;
            int x1 = p - 1;
            int x2 = q - 1;
            arr[1] = x1 * x2;
            arr[2] = x(arr[1], e);
            arr[3] = _POWMOD(C, arr[2], arr[0]);
            return arr[3];

        }
    }
}
