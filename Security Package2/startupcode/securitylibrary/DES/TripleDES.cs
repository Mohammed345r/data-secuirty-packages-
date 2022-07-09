using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, string key)
        {
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string _theCipherP = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string _theTransK = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string LeftDim = "", RightDim = "";
            int i = 0;
            while (i < _theCipherP.Length / 2)
            {
                LeftDim += _theCipherP[i];
                RightDim += _theCipherP[i + _theCipherP.Length / 2];
                i += 1;
            }
            string _TempKey = "";
            List<string> _theLC = new List<string>(); List<string> _theLD = new List<string>();
            i = 0;
            while (i < 8)
            {
                for (int j = 0; j < 7;)
                {
                    _TempKey += _theTransK[PC_1[i, j] - 1];
                    j += 1;
                }
                i += 1;
            }
            string _SC = _TempKey.Substring(0, 28), _SD = _TempKey.Substring(28, 28);

            string _TempT = ""; i = 0;
            for (; i <= 16; i++)
            {
                _theLC.Add(_SC);
                _theLD.Add(_SD);
                _TempT = "";
                switch (i)
                {
                    case 0:
                    case 1:
                    case 8:
                    case 15:
                        _TempT += _SC[0];
                        _SC = _SC.Remove(0, 1);
                        _SC += _TempT;
                        _TempT = "";
                        _TempT += _SD[0];
                        _SD = _SD.Remove(0, 1);
                        _SD += _TempT;
                        break;
                    default:
                        _TempT += _SC.Substring(0, 2);
                        _SC = _SC.Remove(0, 2);
                        _SC += _TempT;
                        _TempT = "";
                        _TempT += _SD.Substring(0, 2);
                        _SD = _SD.Remove(0, 2);
                        _SD += _TempT;
                        break;
                }
            }

            List<string> keys = new List<string>();
            i = 0;
            bool _Cond1 = i < _theLD.Count;
            for (; _Cond1;)
            {
                keys.Add(_theLC[i] + _theLD[i]);
                i += 1;
                _Cond1 = i < _theLD.Count;
            }

            List<string> _NumK = new List<string>();
            for (int k = 1; k < keys.Count;)
            {
                _TempKey = ""; _TempT = ""; _TempT = keys[k];
                i = 0;
                while (i < 8)
                {
                    int j = 0;
                    while (j < 6)
                    {
                        _TempKey += _TempT[PC_2[i, j] - 1];
                        j += 1;
                    }
                    i += 1;
                }

                _NumK.Add(_TempKey);
                k += 1;
            }


            string _II = "";
            i = 0; bool _OtCond = i < 8;
            while (_OtCond)
            {
                int j = 0;
                for (; j < 8; j += 1)
                {
                    _II += _theCipherP[IP[i, j] - 1];
                }
                i += 1;
                _OtCond = i < 8;
            }

            List<string> _LL = new List<string>(), _LR = new List<string>();
            string _SL = _II.Substring(0, 32), _SR = _II.Substring(32, 32);
            _LL.Add(_SL);
            _LR.Add(_SR);
            string _theX = "", _theH = "", Edtawy = "", EXEk = "", _theT = "";
            List<string> _XB = new List<string>();
            int _RR = 0, _CC = 0;
            string _TCB = "", _PS = "", _LOF = "";
            i = 0; bool _Ot2Cond = i < 16;
            for (; _Ot2Cond;)
            {
                _LL.Add(_SR); EXEk = ""; Edtawy = ""; _LOF = ""; _PS = "";
                _XB.Clear();
                _TCB = ""; _CC = 0; _RR = 0; _theT = "";
                int j = 0;
                while (j < 8)
                {
                    int k = 0;
                    while (k < 6)
                    {
                        Edtawy += _SR[EB[j, k] - 1];
                        k += 1;
                    }
                    j += 1;
                }

                for (int g = 0; g < Edtawy.Length;)
                {
                    EXEk += (_NumK[_NumK.Count - 1 - i][g] ^ Edtawy[g]).ToString();
                    g += 1;
                }

                for (int z = 0; z < EXEk.Length;)
                {
                    _theT = "";
                    int y = z;
                    bool _iiCond2 = y < 6 + z;
                    for (; _iiCond2;)
                    {
                        int LocV = 6;
                        if (LocV + z <= EXEk.Length)
                            _theT = _theT + EXEk[y];
                        y += 1;
                        _iiCond2 = y < LocV + z;
                    }

                    _XB.Add(_theT);
                    z += 6;
                }

                _theT = "";
                int _thePS = 0;
                int s = 0;
                for (; s < _XB.Count;)
                {
                    _theT = _XB[s];
                    _theX = _theT[0].ToString() + _theT[5]; _theH = _theT[1].ToString() + _theT[2] + _theT[3] + _theT[4];
                    _RR = Convert.ToInt32(_theX, 2); _CC = Convert.ToInt32(_theH, 2);
                    if (s == 0)
                        _thePS = s1[_RR, _CC];
                    else if (s == 1)
                        _thePS = s2[_RR, _CC];
                    else if (s == 2)
                        _thePS = s3[_RR, _CC];
                    else if (s == 3)
                        _thePS = s4[_RR, _CC];
                    else if (s == 4)
                        _thePS = s5[_RR, _CC];
                    else if (s == 5)
                        _thePS = s6[_RR, _CC];
                    else if (s == 6)
                        _thePS = s7[_RR, _CC];
                    else if (s == 7)
                        _thePS = s8[_RR, _CC];

                    _TCB += Convert.ToString(_thePS, 2).PadLeft(4, '0');
                    s += 1;
                }
                _theX = ""; _theH = "";
                for (int k = 0; k < 8;)
                {
                    j = 0;
                    for (; j < 4;)
                    {
                        _PS = _PS + _TCB[P[k, j] - 1];
                        j += 1;
                    }
                    k += 1;
                }

                for (int k = 0; k < _PS.Length;)
                {
                    _LOF = _LOF + (_PS[k] ^ _SL[k]).ToString();
                    k += 1;
                }

                _SR = _LOF; _SL = _LL[i + 1]; _LR.Add(_SR);
                i += 1;
                _Ot2Cond = i < 16;
            }

            string r16l16 = _LR[16] + _LL[16];
            string ciphertxt = "";
            i = 0;
            while (i < 8)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt += r16l16[IP_1[i, j] - 1];
                }
                i += 1;
            }
            string _thePlT = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0');
            return _thePlT;
        }
        public string Encrypt(string plainText, string key)
        {


            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string _thePlainTxt = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string _theLeftDim = "", _theRightDim = "";
            int _LenOfPtxt = _thePlainTxt.Length / 2;
            for (int i = 0; i < _LenOfPtxt; i++)
            {
                _theLeftDim += _thePlainTxt[i];
                int _idx = i + _LenOfPtxt;
                _theRightDim += _thePlainTxt[_idx];
            }

            string _theTransKey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            string _theTempKey = "";
            List<string> _BC = new List<string>(), _BD = new List<string>();

            for (int i = 0; i < 8;)
            {
                int j = 0;
                for (; j < 7;)
                {
                    _theTempKey += _theTransKey[PC_1[i, j] - 1];
                    j += 1;
                }
                i += 1;
            }

            //C and D
            string _SC = _theTempKey.Substring(0, 28), _SD = _theTempKey.Substring(28, 28);
            int kk = 0;
            while (kk < 10)
            {
                kk += 1;
            }
            string _theTmpOfK = "";
            for (int i = 0; i < 17;)
            {
                _BC.Add(_SC);
                _BD.Add(_SD);
                _theTmpOfK = "";
                switch (i)
                {
                    case 0:
                    case 1:
                    case 8:
                    case 15:
                        _theTmpOfK += _SC[0];
                        _SC = _SC.Remove(0, 1);
                        _SC += _theTmpOfK;
                        _theTmpOfK = "";
                        _theTmpOfK += _SD[0];
                        _SD = _SD.Remove(0, 1);
                        _SD += _theTmpOfK;
                        break;
                    default:
                        _theTmpOfK = _theTmpOfK + _SC.Substring(0, 2);
                        _SC = _SC.Remove(0, 2);
                        _SC += _theTmpOfK;
                        _theTmpOfK = "";
                        _theTmpOfK += _SD.Substring(0, 2);
                        _SD = _SD.Remove(0, 2);
                        _SD += _theTmpOfK;
                        break;
                }
                i += 1;
            }
            List<string> _ListOfK = new List<string>();
            for (int i = 0; i < _BD.Count;)
            {
                _ListOfK.Add(_BC[i] + _BD[i]);
                i += 1;
            }
            List<string> _theNumberOfK = new List<string>();
            for (int k = 1; k < _ListOfK.Count;)
            {
                _theTempKey = "";
                _theTmpOfK = "";
                _theTmpOfK = _ListOfK[k];
                for (int i = 0; i < 8;)
                {
                    int j = 0;
                    while (j < 6)
                    {
                        _theTempKey += _theTmpOfK[PC_2[i, j] - 1];
                        j += 1;
                    }
                    i += 1;
                }
                _theNumberOfK.Add(_theTempKey);
                k += 1;
            }

            for (int i = 0; i < 10;)
            {
                i += 1;
            }
            string _theIp = "";
            for (int i = 0; i < 8;)
            {
                int j = 0;
                while (j < 8)
                {
                    _theIp += _thePlainTxt[IP[i, j] - 1];
                    j += 1;
                }
                i += 1;
            }

            List<string> _BL = new List<string>(), _BR = new List<string>();
            string _SL = _theIp.Substring(0, 32), _SR = _theIp.Substring(32, 32);
            _BL.Add(_SL);
            _BR.Add(_SR);
            string x = "", h = "", editawy = "", exork = "", t = "", tsb = "", pp = "", lf = "";
            List<string> _theItemsOfB = new List<string>();
            int _RDim = 0, _LDim = 0;

            for (int i = 0; i < 16;)
            {
                _BL.Add(_SR);
                exork = ""; editawy = ""; lf = ""; pp = "";
                _theItemsOfB.Clear();
                tsb = ""; _LDim = 0; _RDim = 0;
                t = "";
                int j = 0;
                for (; j < 8;)
                {
                    int k = 0;
                    while (k < 6)
                    {
                        editawy += _SR[EB[j, k] - 1];
                        k += 1;
                    }
                    j += 1;
                }

                for (int g = 0; g < editawy.Length;)
                {
                    exork += (_theNumberOfK[i][g] ^ editawy[g]).ToString();
                    g += 1;
                }
                for (int z = 0; z < exork.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exork.Length)
                            t = t + exork[y];
                    }
                    _theItemsOfB.Add(t);
                }

                t = "";
                int sb = 0;
                for (int s = 0; s < _theItemsOfB.Count; s++)
                {
                    t = _theItemsOfB[s];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    _RDim = Convert.ToInt32(x, 2);
                    _LDim = Convert.ToInt32(h, 2);
                    if (s == 0)
                        sb = s1[_RDim, _LDim];
                    else if (s == 1)
                        sb = s2[_RDim, _LDim];
                    else if (s == 5)
                        sb = s6[_RDim, _LDim];
                    else if (s == 6)
                        sb = s7[_RDim, _LDim];
                    else if (s == 7)
                        sb = s8[_RDim, _LDim];
                    else if (s == 2)
                        sb = s3[_RDim, _LDim];
                    else if (s == 3)
                        sb = s4[_RDim, _LDim];
                    else if (s == 4)
                        sb = s5[_RDim, _LDim];

                    tsb += Convert.ToString(sb, 2).PadLeft(4, '0');
                }
                x = ""; h = "";
                for (int k = 0; k < 8;)
                {
                    j = 0;
                    while (j < 4)
                    {
                        pp = pp + tsb[P[k, j] - 1];
                        j += 1;
                    }
                    k += 1;
                }

                for (int k = 0; k < pp.Length;)
                {
                    lf += (pp[k] ^ _SL[k]).ToString();
                    k += 1;
                }

                _SR = lf;
                _SL = _BL[i + 1];
                _BR.Add(_SR);
                i += 1;
            }

            string r16l16 = _BR[16] + _BL[16];
            string _CipherTxT = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    _CipherTxT += r16l16[IP_1[i, j] - 1];
                }
            }
            string _theRtVal = "0x" + Convert.ToInt64(_CipherTxT, 2).ToString("X");
            return _theRtVal;
        }
        public string Decrypt(string cipherText, List<string> key)
        {
            string _thePlainT = "";
            if (_thePlainT == "")
            {
                _thePlainT = Decrypt(cipherText, key[1]);
                _thePlainT = Encrypt(_thePlainT, key[0]);
                _thePlainT = Decrypt(_thePlainT, key[1]);
            }
            return _thePlainT;
        }
        public string Encrypt(string plainText, List<string> key)
        {
            string _theCipherT = "";
            _theCipherT = Decrypt(Encrypt(plainText, key[0]), key[1]);
            _theCipherT = Encrypt(_theCipherT, key[0]);

            return _theCipherT;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}