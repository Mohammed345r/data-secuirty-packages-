using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {

        public static string[,] shtar;
        public static int[,] str;
        public static string[,] mxcar;

        public override string Decrypt(string cipherText, string key)
        {
            int s1 = 0;
            string[] kyxp = new string[11];
            kyxp[0] = key; for (int i = 0; i < 10; i++) kyxp[i + 1] = key_expansion(kyxp[i], i);
            string[,] pn1n = new string[4, 4];
            int s2 = 0;



            if (cipherText[1] != 'x' || cipherText[1] == 'X')
            {

                s1++;

            }

            else if (cipherText[1] == 'x' || cipherText[1] == 'X')
            {

                cipherText = cipherText.Substring(2, 32);

            }

            else
            {
                s2++;
            }

            int L1 = 0;
            int L2 = 0;
            int L3 = 0;



            for

               (L1 = 0, L2 = 0; L1 < 4; L1++)
            {

                for

                   (L3 = 0; L3 < 4; L3++, L2 += 2)
                {


                    string STR2 = cipherText[L2].ToString() + cipherText[L2 + 1];
                    pn1n[L1, L3] = STR2;


                }
            }


            cipherText = add_roundKey(pn1n, kyxp[10]);
            if (cipherText[1] == 'x' && cipherText[1] == 'X')
            {

                L2++;

            }

            else
            {

                cipherText = "0x" + cipherText;

            }

            int a1 = 9;
            cipherText = InvSubBytes(cipherText);
            int a2 = 0;
            cipherText = InvShift_rows(cipherText);
            int a3 = 0;
            int a4 = 0;


            do
            {

                if (cipherText[1] == 'x' || cipherText[1] == 'X') cipherText = cipherText.Substring(2, 32);

                for
                     (a2 = 0, a3 = 0; a2 < 4; a2++)
                {
                    for

                        (a4 = 0; a4 < 4; a4++, a3 += 2)
                    {

                        string STR2 = cipherText[a3].ToString() + cipherText[a3 + 1];
                        pn1n[a2, a4] = STR2;

                    }
                }


                cipherText = add_roundKey(pn1n, kyxp[a1]);
                if (cipherText[1] == 'x' && cipherText[1] == 'X')
                {

                    a2++;

                }

                else
                {

                    cipherText = "0x" + cipherText;

                }


                cipherText = invmix_columns(cipherText);
                cipherText = InvShift_rows(cipherText);
                cipherText = InvSubBytes(cipherText);
                a1--;


            }
            while (a1 > 0);


            if (cipherText[1] != 'x' || cipherText[1] == 'X')
            {

                a1++;

            }

            else if (cipherText[1] == 'x' || cipherText[1] == 'X')
            {

                cipherText = cipherText.Substring(2, 32);

            }

            else
            {
                a2++;
            }

            int m1 = 0;
            int m2 = 0;
            int m3 = 0;

            for

                (m1 = 0, m2 = 0; m1 < 4; m1++)
            {
                for

                    (m3 = 0; m3 < 4; m3++, m2 += 2)
                {
                    string STR2;

                    STR2 = cipherText[m2].ToString() + cipherText[m2 + 1];

                    pn1n[m1, m3] = STR2;
                }
            }


            cipherText = add_roundKey(pn1n, kyxp[0]);

            return "0x" + cipherText;
        }

        public override string Encrypt(string plainText, string key)
        {

            string[,] pn1n = new string[4, 4];
            int i1 = 0;
            int i2 = 0;

            if (plainText[1] != 'x' || plainText[1] == 'X')
            {

                i1++;

            }

            else if (plainText[1] == 'x' || plainText[1] == 'X')
            {

                plainText = plainText.Substring(2, 32);

            }

            else
            {

                i2++;

            }

            int ml1 = 0;
            int ml2 = 0;
            int ml3 = 0;
            for (ml1 = 0, ml2 = 0; ml1 < 4; ml1++)
            {
                for (ml3 = 0; ml3 < 4; ml3++, ml2 += 2)
                {
                    string STR2;
                    STR2 = plainText[ml2].ToString() + plainText[ml2 + 1];
                    pn1n[ml1, ml3] = STR2;
                }
            }


            plainText = add_roundKey(pn1n, key);
            int ni = 0;


            do
            {

                plainText = SubWord(plainText);
                plainText = ShiftRows(plainText);
                plainText = mix_col(plainText);


                if (plainText[1] != 'x' || plainText[1] == 'X')
                {

                    i2++;

                }

                else if (plainText[1] == 'x' || plainText[1] == 'X')
                {

                    plainText = plainText.Substring(2, 32);

                }
                else
                {

                    i1++;

                }


                int nl1 = 0;
                key = key_expansion(key, ni);
                int nl2 = 0;
                int nl3 = 0;

                for (nl1 = 0, nl2 = 0; nl1 < 4; nl1++)
                {
                    for (nl3 = 0; nl3 < 4; nl3++, nl2 += 2)
                    {

                        string STR2;
                        STR2 = plainText[nl2].ToString() + plainText[nl2 + 1];
                        pn1n[nl1, nl3] = STR2;
                    }
                }
                plainText = add_roundKey(pn1n, key);
                ni++;
            }
            while (ni < 9);


            plainText = SubWord(plainText);
            plainText = ShiftRows(plainText);
            key = key_expansion(key, 9);
            int t1 = 0;
            int t2 = 0;
            int t3 = 0;

            for
                (t1 = 0, t3 = 0; t1 < 4; t1++)
            {
                for
                    (t2 = 0; t2 < 4; t2++, t3 += 2)
                {

                    string ss = plainText[t3].ToString() + plainText[t3 + 1];
                    pn1n[t1, t2] = ss;

                }
            }


            plainText = add_roundKey(pn1n, key);
            return "0x" + plainText;
        }




        private static int multi01(int nm)
        {

            return nm;

        }


        private static int multi02(int nm)
        {

            nm = nm << 1;
            if ((nm & 256) != 0)
            {

                nm -= 256;
                nm ^= 27;

            }
            return nm;

        }

        private static int multi03(int nm)
        {

            return (multi02(nm) ^ nm);

        }


        public static string HTD(string vl)
        {


            int dcm = int.Parse(vl, System.Globalization.NumberStyles.HexNumber);
            string nm;

            nm = dcm.ToString();
            return nm;
        }
        public static string DTH(int dc)
        {
            if (dc < 1)
            {
                return "0";
            }

            int hx;
            hx = dc;
            string hxst = string.Empty;


            do
            {
                hx = dc % 16;

                if (hx < 10)
                    hxst = hxst.Insert(0, Convert.ToChar(hx + 48).ToString());
                else
                    hxst = hxst.Insert(0, Convert.ToChar(hx + 55).ToString());

                dc = dc / 16;

            } while (dc > 0);

            return hxst;
        }
        public static string SubWord(string pln)
        {

            List<string> sbpln = new List<string>();

            string[,] bx ={
                                           { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                                           { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                                           { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                                           {  "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
                                           { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                                           { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                                           { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                                           { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                                           { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                                           { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                                           { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                                           { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                                           {  "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
                                           { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                                           { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                                           { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" }

                                        }; List<string> nwpn = new List<string>();
            int lm = 0;
            do
            {
                if (pln[lm] == 'B' || pln[lm] == 'b')
                    nwpn.Add("11");
                else if (pln[lm] == 'A' || pln[lm] == 'a')
                    nwpn.Add("10");
                else if (pln[lm] == 'D' || pln[lm] == 'd')
                    nwpn.Add("13");
                else if (pln[lm] == 'C' || pln[lm] == 'c')
                    nwpn.Add("12");
                else if (pln[lm] == 'F' || pln[lm] == 'f')
                    nwpn.Add("15");
                else if (pln[lm] == 'E' || pln[lm] == 'e')
                    nwpn.Add("14");

                else
                    nwpn.Add(pln[lm].ToString()); lm++;
            }
            while (lm < pln.Length);
            int lk = 0;
            do
            {
                sbpln.Add(bx[int.Parse(nwpn[lk]), int.Parse(nwpn[lk + 1])]);

                lk += 2;
            }
            while (lk < nwpn.Count - 1);

            string tmst = "";
            int lk2 = 0;
            do
            {
                tmst += sbpln[lk2];

                lk2++;
            }
            while (lk2 < sbpln.Count);


            return tmst;
        }

        public static string mix_col(string st)
        {
            string ssss = ShiftRows(st);
            string[,] shartm = new string[4, 4];
            int cntstar2 = 0;
            int a1 = 0;
            int a2 = 0;
            do
            {
                for (a2 = 0; a2 < 4; a2++)
                {

                    shartm[a2, a1] = st[cntstar2].ToString() + st[cntstar2 + 1].ToString();
                    cntstar2 += 2;
                }
                a1++;
            } while (a1 < 4);

            int[,] tmar = new int[4, 4];

            int b1 = 0;
            int b2 = 0;





            for
               (b1 = 0; b1 < 4; b1++)
            {
                for
                   (b2 = 0; b2 < 4; b2++)
                {
                    tmar[b1, b2] = int.Parse(HTD(shartm[b1, b2]));
                }

            }

            string[,] stmp = new string[4, 4];
            int c1 = 0;
            int c2 = 0;

            for

                (c1 = 0; c1 < 4; c1++)
            {
                for

                    (c2 = 0; c2 < 4; c2++)
                {
                    stmp[c1, c2] = tmar[c1, c2].ToString();

                }
            }

            str = new int[4, 4];
            mxcar = new string[4, 4];
            int vl = 0;

            do
            {

                str[0, vl] = (multi02(int.Parse(stmp[0, vl])) ^ multi03(int.Parse(stmp[1, vl])) ^
                                           multi01(int.Parse(stmp[2, vl])) ^ multi01(int.Parse(stmp[3, vl])));

                str[1, vl] = (multi01(int.Parse(stmp[0, vl])) ^ multi02(int.Parse(stmp[1, vl])) ^
                                         multi03(int.Parse(stmp[2, vl])) ^ multi01(int.Parse(stmp[3, vl])));

                str[2, vl] = (multi01(int.Parse(stmp[0, vl])) ^ multi01(int.Parse(stmp[1, vl])) ^
                                           multi02(int.Parse(stmp[2, vl])) ^ multi03(int.Parse(stmp[3, vl])));
                str[3, vl] = (multi03(int.Parse(stmp[0, vl])) ^ multi01(int.Parse(stmp[1, vl])) ^
                                           multi01(int.Parse(stmp[2, vl])) ^ multi02(int.Parse(stmp[3, vl])));

                vl++;
            }
            while (vl < 4);


            int d1 = 0;
            int d2 = 0;
            do
            {
                for (d2 = 0; d2 < 4; d2++)
                {
                    mxcar[d1, d2] = DTH(str[d1, d2]);
                }

                d1++;
            }
            while (d1 < 4);


            int e1 = 0;
            int e2 = 0;
            do
            {
                for (e2 = 0; e2 < 4; e2++)
                {
                    if (mxcar[e1, e2].Length < 2)
                    {
                        mxcar[e1, e2] = "0" + mxcar[e1, e2];
                    }
                }
                e1++;
            }
            while (e1 < 4);


            ssss = "";
            int f1 = 0;
            int f2 = 0;
            do
            {
                for (f2 = 0; f2 < 4; f2++)
                {
                    ssss += mxcar[f2, f1];
                }
                f1++;
            }
            while (f1 < 4);

            return ssss;
        }


        public static string ShiftRows(string st)
        {
            int cnt = 0;
            double xl = Math.Sqrt(st.Length / 2);
            string[,] arry = new string[(int)xl, (int)xl];
            List<string> tmlst = new List<string>();
            string yn = "";

            int il = 0;
            while (il < st.Length - 1)
            {
                yn = st[il].ToString() + st[il + 1].ToString();
                tmlst.Add(yn);
                il += 2;
            }

            il = 0;
            while (il < xl)
            {
                int j = 0;
                while (j < xl)
                {
                    arry[j, il] = tmlst[cnt];
                    cnt++;
                    j++;

                }

                il++;

            }


            shtar = new string[(int)xl, (int)xl];

            il = 0;
            while (il < 1)
            {
                int j = 0;
                while (j < xl)
                {
                    shtar[il, j] = arry[il, j];
                    j++;
                }

                il++;
            }




            il = 1;
            while (il < xl)
            {


                int j = 0;
                while (j < xl)
                {
                    shtar[il, j] = arry[il, ((j + il) % (int)xl)];
                    j++;


                }

                il++;

            }
            string qq = "";

            il = 0;
            while (il < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    qq += shtar[j, il];
                    j++;
                }

                il++;
            }
            return qq;
        }

        public static string[] rot_word(string[] W)
        {
            string[] res = new string[4];
            res[0] = W[1];
            res[1] = W[2];
            res[2] = W[3];
            res[3] = W[0];
            return res;
        }
        static string key_expansion(string key, int round)
        {
            string[,] S_box ={
            {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
            {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
            {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
            {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
            {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
            {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
            {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
            {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
            {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
            {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
            {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
            {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
            {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
            {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
            {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
            {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
            };
            string[,] R_con =
           {
                { "01" , "02" , "04" , "08" , "10" , "20" , "40" , "80" , "1b" , "36"},
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" }



            };
            string[,] new_k = new string[4, 4];

            int i = 0, l = 2;
            while (i < 4)
            {
                int f = 0;
                while (f < 4)
                {
                    string str = key[l].ToString() + key[l + 1].ToString();
                    new_k[f, i] = str;
                    l += 2;
                    f++;
                }

                i++;
            }

            string[] tmp_k = new string[4];
            i = 0;
            while (i < 4)
            {
                tmp_k[i] = new_k[i, 3];

                i++;
            }
            tmp_k = rot_word(tmp_k);
            string rot_tmp = "";
            i = 0;
            while (i < 4)
            {
                rot_tmp += tmp_k[i];
                i++;

            }
            string sub_tmp = "";
            rot_tmp = rot_tmp.ToUpper();
            i = 0;
            while (i < rot_tmp.Length)
            {
                int Index_1 = rot_tmp[i] - '0';
                if (Index_1 > 15) Index_1 -= 7;
                int Index_2 = rot_tmp[i + 1] - '0';
                if (Index_2 > 15) Index_2 -= 7;
                sub_tmp += S_box[Index_1, Index_2];
                i += 2;
            }
            string[,] result_k = new string[4, 4];

            i = 0;
            int j = 0;
            while (i < 4)
            {

                int k = Convert.ToInt32(new_k[i, 0], 16);
                int sub = Convert.ToInt32(sub_tmp.Substring(j, 2), 16);
                int rc = Convert.ToInt32(R_con[i, round], 16);
                int num = k ^ sub ^ rc;
                string str = Convert.ToString(num, 16);
                if (num < 16) result_k[i, 0] = "0" + str;
                else result_k[i, 0] = str;
                i++;
                j += 2;

            }


            i = 1;
            while (i < 4)
            {
                j = 0;
                while (j < 4)
                {
                    int result_key = Convert.ToInt32(result_k[j, i - 1], 16);
                    int k = Convert.ToInt32(new_k[j, i], 16);
                    int num = k ^ result_key;
                    string str = Convert.ToString(num, 16);
                    if (num < 16) result_k[j, i] = "0" + str;
                    else result_k[j, i] = str;
                    j++;
                }

                i++;
            }

            string Res_Key = "0x";

            i = 0;
            while (i < 4)
            {
                j = 0;
                while (j < 4)
                {
                    Res_Key += result_k[j, i];
                    j++;
                }
                i++;
            }


            i = 0;
            while (i < 4)
            {
                j = 0;
                while (j < 4)
                {
                    Console.Write(result_k[i, j]);
                    j++;
                }
                Console.WriteLine();

                i++;

            }
            Console.WriteLine();
            return Res_Key;
        }

        public static string add_roundKey(string[,] p, string k)
        {

            string p_1d = "";

            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    p_1d += p[i, j];
                    j++;
                }

                i++;
            }
            string res = "";

            i = 0;
            while (i < p_1d.Length)
            {
                int pln = Convert.ToInt32(p_1d.Substring(i, 2), 16);
                int k_nm = Convert.ToInt32(k.Substring(i + 2, 2), 16);
                int xr = pln ^ k_nm;
                string str = "";
                if (xr < 16) str = "0" + Convert.ToString(xr, 16);
                else str = Convert.ToString(xr, 16);
                res += str;

                i += 2;

            }
            return res;
        }
        public static string InvSubBytes(string p)
        {
            List<string> new_pla = new List<string>();
            List<string> sub_pla = new List<string>();
            string[,] Sbox_inv ={
                {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
                {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
                {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
                {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
                {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
                {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
                {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
                {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
                {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
                {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
                {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
                {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
                {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
                {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
                {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
                {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"},
            };


            int i = 0;
            while (i < p.Length)
            {
                if (p[i] == 'A' || p[i] == 'a')
                    new_pla.Add("10");
                else if (p[i] == 'B' || p[i] == 'b')
                    new_pla.Add("11");
                else if (p[i] == 'C' || p[i] == 'c')
                    new_pla.Add("12");
                else if (p[i] == 'D' || p[i] == 'd')
                    new_pla.Add("13");
                else if (p[i] == 'E' || p[i] == 'e')
                    new_pla.Add("14");
                else if (p[i] == 'F' || p[i] == 'f')
                    new_pla.Add("15");
                else
                    new_pla.Add(p[i].ToString());


                i++;

            }


            i = 2;
            while (i < new_pla.Count - 1)
            {
                sub_pla.Add(Sbox_inv[int.Parse(new_pla[i]), int.Parse(new_pla[i + 1])]);
                i += 2;
            }

            string tmp_str = "0x";

            i = 0;
            while (i < sub_pla.Count)
            {
                tmp_str += sub_pla[i];
                i++;
            }

            return tmp_str;

        }  // InvS
        public static string InvShift_rows(string result)
        {
            string[,] t = new string[4, 4];
            string[,] plain = new string[4, 4];
            int count = 0;
            List<string> tmp_lst = new List<string>();
            string str = "";

            int i = 2;
            while (i < result.Length)
            {
                str = result[i].ToString() + result[i + 1].ToString();
                tmp_lst.Add(str);
                i += 2;
            }

            i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {

                    plain[j, i] = tmp_lst[count];
                    count++;
                    j++;

                }

                i++;
            }



            i = 0;
            while (i < 1)
            {
                int j = 0;
                while (j < 4)
                {
                    t[i, j] = plain[i, j];
                    j++;
                }

                i++;
            }


            string s = "0x";


            int row = 1;
            while (row < 4)
            {
                int col = 0;
                while (col < 4)
                {
                    t[row, (col + row) % 4] = plain[row, col];
                    ++col;

                }
                ++row;
            }

            i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    s += t[j, i];
                    j++;
                }

                i++;
            }
            return s;
        }
        public string invmix_columns(string result)
        {
            string[,] arrshift_tmp = new string[4, 4];

            int[,] tmp_array = new int[4, 4];
            int count_arf = 2;

            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {

                    arrshift_tmp[j, i] = result[count_arf].ToString() + result[count_arf + 1].ToString();
                    count_arf += 2;
                    j++;

                }

                i++;
            }

            i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    tmp_array[j, i] = int.Parse(HTD(arrshift_tmp[j, i]));
                    j++;
                }

                i++;
            }
            string[,] tp = new string[4, 4];

            i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    tp[i, j] = tmp_array[i, j].ToString();
                    j++;

                }

                i++;
            }
            int[,] pl = new int[4, 4];
            string[,] mix_co_array = new string[4, 4];


            int col = 0;
            while (col < 4)
            {
                pl[0, col] = (gfmultby0e(int.Parse(tp[0, col])) ^ gfmultby0b(int.Parse(tp[1, col])) ^
                                           gfmultby0d(int.Parse(tp[2, col])) ^ gfmultby09(int.Parse(tp[3, col])));
                pl[1, col] = (gfmultby09(int.Parse(tp[0, col])) ^ gfmultby0e(int.Parse(tp[1, col])) ^
                                           gfmultby0b(int.Parse(tp[2, col])) ^ gfmultby0d(int.Parse(tp[3, col])));
                pl[2, col] = (gfmultby0d(int.Parse(tp[0, col])) ^ gfmultby09(int.Parse(tp[1, col])) ^
                                           gfmultby0e(int.Parse(tp[2, col])) ^ gfmultby0b(int.Parse(tp[3, col])));
                pl[3, col] = (gfmultby0b(int.Parse(tp[0, col])) ^ gfmultby0d(int.Parse(tp[1, col])) ^
                                           gfmultby09(int.Parse(tp[2, col])) ^ gfmultby0e(int.Parse(tp[3, col])));
                ++col;
            }

            i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    mix_co_array[i, j] = DTH(pl[i, j]);
                    j++;

                }
                i++;

            }


            i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    if (mix_co_array[i, j].Length == 2)
                    {
                        col++;
                    }
                    else
                    {
                        mix_co_array[i, j] = "0" + mix_co_array[i, j];
                    }

                    j++;

                }
                i++;

            }
            string pstr = "0x";

            i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    pstr += mix_co_array[j, i];
                    j++;
                }

                i++;
            }
            return pstr;
        }

        public static int gfmultby09(int b)
        {
            return (multi02(multi02(multi02(b))) ^ b);
        }
        public static int gfmultby0b(int b)
        {
            return (multi02(multi02(multi02(b))) ^
                           multi02(b) ^
                           b);
        }
        public static int gfmultby0d(int b)
        {
            return (multi02(multi02(multi02(b))) ^
                           multi02(multi02(b)) ^
                           (b));
        }
        public static int gfmultby0e(int b)
        {
            return (multi02(multi02(multi02(b))) ^
                           multi02(multi02(b)) ^
                           multi02(b));
        }
    }
}