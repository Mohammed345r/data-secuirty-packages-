using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public struct KOMatrices
    {
        public Dictionary<char, Tuple<int, int>> KM;
        public List<List<char>> OM;
    }


    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        /// 
        public HashSet<char> ModifiedKey(string key)
        {
            string _englishAlphabet = "abcdefghiklmnopqrstuvwxyz";
            HashSet<char> Mkey = new HashSet<char>(); // stored key + Alphabetic 
            int _lengthOfKey = key.Length;
            // first loop ( mapping key letter to list and make (i/j) together)
            int indx1 = 0;
            do
            {
                if (key[indx1] != 'j')
                {
                    Mkey.Add(key[indx1]);
                }
                else
                {
                    Mkey.Add('i');
                }
                indx1 = indx1 + 1;
            } while (indx1 < _lengthOfKey);
            // second loop (adding english letter  to list)
            int indx2 = 0;
            do
            {
                Mkey.Add(_englishAlphabet[indx2]);
                indx2 = indx2 + 1;
            } while (indx2 < 25);
            return Mkey;
        }
        public KOMatrices KOFunc(HashSet<char> Mkey)
        {
            Dictionary<char, Tuple<int, int>> KMatrix = new Dictionary<char, Tuple<int, int>>();
            List<List<char>> OMatrix = new List<List<char>>();
            int cntr = 0;
            int outerindx = 0;
            do
            {
                List<char> _temp = new List<char>();
                int innerindx = 0;
                do
                {
                    if (cntr < 25)
                    {
                    
                        KMatrix.Add(Mkey.ElementAt(cntr), new Tuple<int, int>(outerindx, innerindx));
                        // (row column) add element by element in one row in list
                        _temp.Add(Mkey.ElementAt(cntr)); // add 
                        cntr = cntr + 1;
                    }
                    innerindx = innerindx + 1;
                } while (innerindx < 5);
                OMatrix.Add(_temp); // add row by row in matrix
                outerindx = outerindx + 1;
            } while (outerindx < 5);
            KOMatrices _komatrix = new KOMatrices();
            _komatrix.KM = KMatrix;
            _komatrix.OM = OMatrix;

            return _komatrix;
        }
        public List<string> divideIt(string x) // apply in decrypt as cut txt to blocks
        {
            List<string> _largeOfString = new List<string>();
            // c ==> chunk
            int c = 100,
                ln = x.Length;
            int indx = 0;
            do
            {
                int comp = indx + c;
                if (comp > ln)
                {
                    c = ln - indx;
                }
                _largeOfString.Add(x.Substring(indx, c));
                indx = indx + c;
            } while (indx < ln);
            return _largeOfString;
        }
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
            
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();

        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();

            List<string> SmallCHAR = new List<string>();

            bool flag = false;
            if (cipherText.Length >= 100)
            {
                SmallCHAR = divideIt(cipherText);
                flag = true;
            }

            KOMatrices matrix = KOFunc(ModifiedKey(key));
            string text = "";
            for (int j = 0; j < SmallCHAR.Count || !flag; j++)
            {
                if (flag)
                {
                    cipherText = SmallCHAR[j];
                }


                int CTLength = cipherText.Length;
                string word2 = "";
                flag = true;



                for (int i = 0; i < CTLength; i += 2)
                {

                    char char1 = cipherText[i];
                      char char2 = cipherText[i + 1];

                    
                     if (matrix.KM[char1].Item1 == matrix.KM[char2].Item1) //same column
                    {
                        word2 += matrix.OM[matrix.KM[char1].Item1][(matrix.KM[char1].Item2 +4) % 5];
                        word2 += matrix.OM[matrix.KM[char2].Item1][(matrix.KM[char2].Item2 +4) % 5];
                    }
                    else if (matrix.KM[char1].Item2 == matrix.KM[char2].Item2) //same row
                    {
                        word2 += matrix.OM[(matrix.KM[char1].Item1 +4) % 5][matrix.KM[char1].Item2];
                        word2 += matrix.OM[(matrix.KM[char2].Item1 +4) % 5][matrix.KM[char2].Item2];
                    }
                    else //diagonal
                    {
                        word2 += matrix.OM[matrix.KM[char1].Item1][matrix.KM[char2].Item2];
                        word2 += matrix.OM[matrix.KM[char2].Item1][matrix.KM[char1].Item2];
                    }
                }


                string var = word2;

               

                 if (word2[word2.Length - 1] == 'x')
                { 
                    var = var.Remove(word2.Length - 1);
                }

                int matrem = 0;
                int z;
                for ( z = 0; z < var.Length; z++)
                {
                    if (word2[z] == 'x')
                    {
                        if (word2[z - 1] == word2[z + 1])
                        {
                            if (z + matrem < var.Length && (z - 1) % 2 == 0)
                            {
                                var = var.Remove(z + matrem, 1);
                                matrem--;
                            }
                        }
                    }
                }

                text += var;
            }

            Console.WriteLine(text);
            return text;
        }
        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            string CT = "";

            KOMatrices KOkey = KOFunc(ModifiedKey(key));
            int i;
            for ( i = 0; i < plainText.Length - 1; i += 2) // i+=2 as p.t (block of 2 char)
            {
                if (plainText[i] == plainText[i + 1]) // if repeat add 'x'
                {
                    plainText = plainText.Substring(0, i + 1) + 'x' + plainText.Substring(i + 1);
                }

            }
            if (plainText.Length % 2 == 1) // if last char is 1 then add 'x' to it
            {
                plainText += 'x';
            }


           
            int j;
            for ( j = 0; j < plainText.Length; j += 2)
            {


                char char1 = plainText[j], char2 = plainText[j + 1];
                if (KOkey.KM[char1].Item2 == KOkey.KM[char2].Item2) //same column 
                {
                    CT += KOkey.OM[(KOkey.KM[char1].Item1 + 1) % 5][KOkey.KM[char1].Item2];
                    CT += KOkey.OM[(KOkey.KM[char2].Item1 + 1) % 5][KOkey.KM[char2].Item2];
                }
                else if (KOkey.KM[char1].Item1 == KOkey.KM[char2].Item1)//same row
                {
                    CT += KOkey.OM[KOkey.KM[char1].Item1][(KOkey.KM[char1].Item2 + 1) % 5];
                    CT += KOkey.OM[KOkey.KM[char2].Item1][(KOkey.KM[char2].Item2 + 1) % 5];
                }
                else // diagonal
                {
                    CT += KOkey.OM[KOkey.KM[char1].Item1][KOkey.KM[char2].Item2];
                    CT += KOkey.OM[KOkey.KM[char2].Item1][KOkey.KM[char1].Item2];
                }
            }


            Console.WriteLine(CT.ToUpper());
            Console.WriteLine("\n\n");
            return CT.ToUpper();








        }
    }
}
