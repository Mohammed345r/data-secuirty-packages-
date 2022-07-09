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
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            int[,] arr1;
            arr1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] arr2;
            arr2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };
            int[,] r2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] r4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] r5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] r1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] r3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] r6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] r7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] r8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
            int[,] mac = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };
            int[,] ipp = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };
            int[,] hj = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
            int[,] cr7 = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
            string bi = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0'), bik = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0'), LLMM = "", RRMM = "";
            int i1 = 0;
            int balaha = bi.Length / 2;
            while (i1 < balaha)
            {
                LLMM = LLMM + bi[i1];
                RRMM = RRMM + bi[i1 + balaha];
                i1 -= -1;
            }
            string temp2 = "";
            List<string> CC;
            CC = new List<string>();
            List<string> D;
            D = new List<string>();
            int i2 = 0;
            while (i2 < 8)
            {
                int i3 = 0;
                do
                {
                    temp2 = temp2 + bik[arr1[i2, i3] - 1];
                    i3++;
                } while (i3 < 7);
                i2++;
            }
            string cc = temp2.Substring(0, 28), dd = temp2.Substring(28, 28), tmp = "";
            int i4 = 0;
            do
            {
                CC.Add(cc);
                D.Add(dd);
                tmp = "";
                switch (i4)
                {
                    case 0:
                    case 1:
                    case 8:
                    case 15:
                        {
                            tmp = tmp + cc[0];
                            cc = cc.Remove(0, 1);
                            cc = cc + tmp;
                            tmp = "";
                            tmp = tmp + dd[0];
                            dd = dd.Remove(0, 1);
                            dd = dd + tmp;
                            break;
                        }
                    default:
                        {
                            tmp = tmp + cc.Substring(0, 2);
                            cc = cc.Remove(0, 2);
                            cc = cc + tmp;
                            tmp = "";
                            tmp = tmp + dd.Substring(0, 2);
                            dd = dd.Remove(0, 2);
                            dd = dd + tmp;
                            break;
                        }
                }
                i4++;
            } while (i4 <= 16);

            List<string> kkk;
            kkk = new List<string>();
            int rr = D.Count, ind = 0;
            while (ind < rr)
            {
                kkk.Add(CC[ind] + D[ind]);
                ind -= -1;
            }
            List<string> nkkk;
            nkkk = new List<string>();
            int fg1 = 0;
            do
            {
                temp2 = "";
                tmp = "";
                tmp = kkk[fg1];
                for (int e = 0; e < 8; e++)
                {
                    int u = 0;
                    while (u < 6)
                    {
                        temp2 = temp2 + tmp[arr2[e, u] - 1];
                        u++;
                    }
                }
                nkkk.Add(temp2);
                fg1++;
            } while (fg1 < kkk.Count);
            string IP = "";
            int ds = 0;
            do
            {
                int sd = 0;
                do
                {
                    IP = IP + bi[mac[ds, sd] - 1];
                    sd++;
                } while (sd < 8);
                ds++;
            } while (ds < 8);
            List<string> LLL;
            LLL = new List<string>();
            List<string> RRR;
            RRR = new List<string>();
            string lrt = IP.Substring(0, 32), rtl = IP.Substring(32, 32);
            LLL.Add(lrt);
            RRR.Add(rtl);
            string tt = "", tsb = "", pp = "", lf = "";
            string fff = "", ffff = "", hat = "", him = "";
            List<string> lsst = new List<string>();
            int varzer = 0, r = varzer, c = varzer;

            int indexawe = 0;
            while (indexawe < 16)
            {
                LLL.Add(rtl);
                him = "";
                hat = "";
                lf = "";
                pp = "";
                lsst.Clear();
                tsb = "";
                c = 0;
                r = 0;
                tt = "";
                int ind1 = 0;
                while (ind1 < 8)
                {
                    int ind2 = 0;
                    while (ind2 < 6)
                    {
                        hat = hat + rtl[cr7[ind1, ind2] - 1];
                        ind2++;
                    }
                    ind1++;
                }

                int mgg = 0;
                while (mgg < hat.Length)
                {
                    him = him + (nkkk[nkkk.Count - 1 - indexawe][mgg] ^ hat[mgg]).ToString();
                    mgg++;
                }

                int ssd = 0;
                while (ssd < him.Length)
                {
                    tt = "";
                    int y = ssd;
                    while (y < 6 + ssd)
                    {
                        if (6 + ssd <= him.Length)
                            tt = tt + him[y];
                        y++;
                    }

                    lsst.Add(tt);
                    ssd += 6;
                }

                tt = "";
                int sb = 0;
                int s = 0;
                while (s < lsst.Count)
                {
                    tt = lsst[s];
                    fff = tt[0].ToString() + tt[5];
                    ffff = tt[1].ToString() + tt[2] + tt[3] + tt[4];

                    r = Convert.ToInt32(fff, 2);
                    c = Convert.ToInt32(ffff, 2);
                    //
                    switch (s)
                    {
                        case 0:
                            {
                                sb = r1[r, c];
                                break;
                            }
                        case 1:
                            {
                                sb = r2[r, c];
                                break;
                            }
                        case 2:
                            {
                                sb = r3[r, c];
                                break;
                            }
                        case 3:
                            {
                                sb = r4[r, c];
                                break;
                            }
                        case 4:
                            {
                                sb = r5[r, c];
                                break;
                            }
                        case 5:
                            {
                                sb = r6[r, c];
                                break;
                            }
                        case 6:
                            {
                                sb = r7[r, c];
                                break;
                            }
                        case 7:
                            {
                                sb = r8[r, c];
                                break;
                            }
                        default:
                            {
                                break;
                            }
                    }
                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                    s++;
                }

                fff = "";
                ffff = "";
                int xy = 0;
                while (xy < 8)
                {
                    int yx = 0;
                    while (yx < 4)
                    {
                        pp = pp + tsb[hj[xy, yx] - 1];
                        yx++;
                    }
                    xy++;
                }
                int ko = 0;
                while (ko < pp.Length)
                {
                    lf = lf + (pp[ko] ^ lrt[ko]).ToString();
                    ko++;
                }

                rtl = lf;
                lrt = LLL[indexawe + 1];
                RRR.Add(rtl);
                indexawe++;
            }

            string r16l16 = RRR[16] + LLL[16], ct = "";
            int ih = 0;
            while (ih < 8)
            {
                int jh = 0;
                while (jh < 8)
                {
                    ct = ct + r16l16[ipp[ih, jh] - 1];
                    jh++;
                }
                ih++;
            }
            string ptr;
            ptr = "0x" + Convert.ToInt64(ct, 2).ToString("X").PadLeft(16, '0');
            return ptr;
        }
        public override string Encrypt(string plainText, string key)
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


            string blanctext = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string vgvhgsdvh = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string leftmeen = "";
            string rightmeen = "";
            int lenth1 = (blanctext.Length / 2);
            for (int i = 0; i < lenth1; i++)
            {
                leftmeen = leftmeen + blanctext[i];
                rightmeen = rightmeen + blanctext[i + lenth1];
            }

            //premutate key by pc-1
            string gygshav = "";
            List<string> C = new List<string>();
            List<string> D = new List<string>();
            string[] arr1 = { };
            string[] arr2 = { };
            int eiht = 8;
            int seven = 7;
            int zxx = 0;

           while(zxx < eiht)
            {
                for ( int j = 0; j < seven; j++)
                {
                    gygshav = gygshav + vgvhgsdvh[PC_1[zxx, j] - 1];
                }
                zxx++;
            }

            //C and D
            string c = gygshav.Substring(0, 28);
            string d = gygshav.Substring(28, 28);

            string temp = "";
            int gfg=16;
            for (int i = 0; i <= gfg; i++)
            {
                C.Add(c);
                D.Add(d);
                temp = "";
                switch (i)
                {
                    case 0:
                    case 1:
                    case 8:
                    case 15:
                    temp = temp + c[0];
                c = c.Remove(0, 1);
                c = c + temp;
                temp = "";
                temp = temp + d[0];
                d = d.Remove(0, 1);
                d = d + temp;
                        break;
                     default:
                        temp = temp + c.Substring(0, 2);
                        c = c.Remove(0, 2);
                        c = c + temp;
                        temp = "";
                        temp = temp + d.Substring(0, 2);
                        d = d.Remove(0, 2);
                        d = d + temp;
                        break;
            }
               
               
            }

            List<string> keys = new List<string>();
            int hghg = 0;
            while(hghg< D.Count)
            {
                keys.Add(C[hghg] + D[hghg]);
                hghg++;
            }


           

            //k1 --> k16 by pc-2
            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                gygshav = "";
                temp = "";
                temp = keys[k];
                int gggggg = 0;
                int tyui = 8;
                int hhhh = 6;
                while (gggggg< tyui)
                {
                    for (int j = 0; j < hhhh; j++)
                    {
                        gygshav = gygshav + temp[PC_2[gggggg, j] - 1];
                    }
                    gggggg++;
                }

                nkeys.Add(gygshav);
            }
            

            //premutation by IP for plain text
            string ip = "";
            int aaaaa = 0;
            while (aaaaa<8)
            {
                for (int j = 0; j < 8; j++)
                {
                    ip = ip + blanctext[IP[aaaaa, j] - 1];
                }
                aaaaa++;
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ip.Substring(0, 32);
            string r = ip.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebit = "";
            string exork = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                L.Add(r);
                exork = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                int bbbbb = 0;
                
                while (bbbbb<8)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebit = ebit + r[EB[bbbbb, k] - 1];
                    }
                    bbbbb++;
                }
                int ddddd = 0;
                while (ddddd < ebit.Length)
                {
                    exork = exork + (nkeys[i][ddddd] ^ ebit[ddddd]).ToString();
                    ddddd++;
                }
                int eeee = 0;
                while (eeee < exork.Length )
                {
                    t = "";
                    for (int y = eeee; y < 6 + eeee; y++)
                    {
                        if (6 + eeee <= exork.Length)
                            t = t + exork[y];
                    }
                    eeee = eeee + 6;

                    sbox.Add(t);
                }

                t = "";
                int sb = 0;
                int ddddddd = 0;
                while (ddddddd < sbox.Count )
                {
                    t = sbox[ddddddd];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    switch (ddddddd)
                    {

                        case 0:
                            sb = s1[row, col];
                            break;
                        case 1:
                            sb = s2[row, col];
                            break;
                        case 2:
                            sb = s3[row, col];
                            break;
                        case 3:
                            sb = s4[row, col];
                            break;
                        case 4:
                            sb = s5[row, col];
                            break;
                        case 5:
                            sb = s6[row, col];
                            break;
                        case 6:
                            sb = s7[row, col];
                            break;
                        default:
                            sb = s8[row, col];
                            break;



                    }
                  
                    ddddddd++;

                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                x = "";
                h = "";
                int fffff = 0;
                while (fffff < 8)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp = pp + tsb[P[fffff, j] - 1];
                    }
                    fffff++;
                }
                int ggggg = 0;
                while (ggggg < pp.Length)
                {
                    lf = lf + (pp[ggggg] ^ l[ggggg]).ToString();
                    ggggg++;
                }

                r = lf;
                l = L[i + 1];
                R.Add(r);
            }

            

            string r16l16 = R[16] + L[16];
            string ciphertxt = "";
            int gggg = 0;
            while (gggg < 8)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + r16l16[IP_1[gggg, j] - 1];
                }
                gggg++;
            }
            string ct = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X");

            return ct;
        }
    }
}