using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        // 2 power 5
        // 2*2*2*2*2
        public int _POWMOD(int n1, int n2, int M, float f = 0)
        {
            int p = 1, i = 0;
            for (; ; )
            {
                if (i < n2) // power
                {
                    p *= n1; // base
                    p %= M; // calculate (m mod)
                    i++;
                }
                else
                {
                    break;
                }

            }
            return p;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int[] arr = new int[4];
            //public key = alpha ^ xa mod q
            arr[0] = _POWMOD(alpha, xa, q);
            arr[1] = _POWMOD(alpha, xb, q);
            // secret key A = pubB ^ xa mod q  
            arr[2] = _POWMOD(arr[1], xa, q);
            // secret key B = pubA ^ xb mod q
            arr[3] = _POWMOD(arr[0], xb, q);
            List<int> res;
            res = new List<int>();
            res.Add(arr[2]);
            res.Add(arr[3]);
            return res;
        }
    }
}
