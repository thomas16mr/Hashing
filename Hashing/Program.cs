using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Sodium;
using System.Net;
using System.IO;
using System.Collections.Specialized;
using Newtonsoft;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace Hashing
{
    class Program
    {
        //public List do ktoreho ulozime dvojice meno,heslo
        public static List<Tuple<string, string>> users = new List<Tuple<string, string>>();

        /// <summary>
        /// Funkcia nacita dvojice meno,heslo zo suboru a ulozi ich do listu
        /// </summary>
        public static void nacitaj()
        {
            int c = 0;
            string[] lines = System.IO.File.ReadAllLines(@"C:\Users\Tomáš Baka\Documents\Visual Studio 2015\Projects\Hashing\Hashing\users.csv");
            foreach (string s in lines)
            {
                string[] tmp = s.Split(';');
               
                    users.Add(new Tuple<string, string>(tmp[0], tmp[1]));
                    c++;
                
            }
            
        }

        /// <summary>
        /// Funkcia prejde cely list dvojic meno,heslo , zahashuje heslo pomocou MD5 bez saltu a posiela request na server kde sa ulozi hash do databazy
        /// </summary>
        public static void naplnMD5S()
        {           
            foreach (Tuple<string, string> t in users)
            {

                string get = MD5_hasher.GenerateHashWithoutSalt(t.Item2);

                JArray array = new JArray();
                array.Add(t.Item1);  //login    
                array.Add(get);      //pass
                array.Add("2");     //index

                JObject o = new JObject();
                o["MyArray"] = array;

                string json = o.ToString();
                //Console.WriteLine(json);
                ConnectionManager.SendData("https://147.175.98.36/insert.php",json);

            }

        }
        /// <summary>
        /// Funkcia prejde cely list dvojic meno,heslo , zahashuje heslo pomocou Argon2 a posiela request na server kde sa ulozi hash do databazy
        /// </summary>
        public static void naplnArgon()
        {            
            foreach (Tuple<string, string> t in users)
            {
                string[] get = Argon2_hasher.GenerateHash(t.Item2, "");              

                JArray array = new JArray();
                array.Add(t.Item1);
                array.Add(get[0]);
                array.Add(get[1]);
                array.Add("3");

                JObject o = new JObject();
                o["MyArray"] = array;

                string json = o.ToString();
                
                ConnectionManager.SendData("https://147.175.98.36/insert.php", json);
            }
        }


        /// <summary>
        /// Funkcia prejde cely list dvojic meno,heslo , zahashuje heslo pomocou MD5 so saltom a posiela request na server kde sa ulozi hash do databazy
        /// </summary>
        public static void naplnMD5()
        {          
            foreach (Tuple<string, string> t in users)
            {

                string[] get = MD5_hasher.GenerateHashWithSalt(t.Item2, "");

                JArray array = new JArray();
                array.Add(t.Item1);
                array.Add(get[0]);
                array.Add(get[1]);
                array.Add("1");

                JObject o = new JObject();
                o["MyArray"] = array;

                string json = o.ToString();
                //Console.WriteLine(json);
                ConnectionManager.SendData("https://147.175.98.36/insert.php",json);

            }
        }

        /// <summary>
        /// Funkcia prejde cely list dvojic meno,heslo , zahashuje heslo pomocou PBKDF2 a posiela request na server kde sa ulozi hash do databazy
        /// </summary>
        static void naplnPBKDF()
        {            
            foreach (Tuple<string, string> t in users)
            {

                string[] get = PKDBF2_hasher.GenerateHash(t.Item2, "");

                JArray array = new JArray();
                array.Add(t.Item1);
                array.Add(get[0]);
                array.Add(get[1]);
                array.Add("4");

                JObject o = new JObject();
                o["MyArray"] = array;

                string json = o.ToString();
                //Console.WriteLine(json);
                ConnectionManager.SendData("https://147.175.98.36/insert.php", json);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public static void md5Plain()
        {
            foreach (Tuple<string, string> t in users)
            {
                JArray array = new JArray();
                array.Add("1");
                array.Add(t.Item1);
                array.Add(t.Item2);
                
                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }
        public static void md5sPlain()
        {
            foreach (Tuple<string, string> t in users)
            {
                JArray array = new JArray();
                array.Add("2");
                array.Add(t.Item1);
                array.Add(t.Item2);

                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }

        public static void argon2Plain()
        {
            foreach (Tuple<string, string> t in users)
            {
                JArray array = new JArray();
                array.Add("3");
                array.Add(t.Item1);
                array.Add(t.Item2);

                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }

        public static void pkbdfPlain()
        {
            foreach (Tuple<string, string> t in users)
            {
                JArray array = new JArray();
                array.Add("4");
                array.Add(t.Item1);
                array.Add(t.Item2);

                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }

        public static void md5QuerySalt()
        {
            foreach (Tuple<string, string> t in users)
            {
                string[] postData = new string[3];
                postData[0] = "1";
                postData[1] = t.Item1;
                postData[2] = t.Item2;
                ConnectionManager.SendData2("https://147.175.98.36/fetch.php", postData);
            }
        }
        public static void argonQuerySalt()
        {
            foreach (Tuple<string, string> t in users)
            {
                string[] postData = new string[3];
                postData[0] = "2";
                postData[1] = t.Item1;
                postData[2] = t.Item2;
                ConnectionManager.SendData2("https://147.175.98.36/fetch.php", postData);
            }
        }

        public static void pbkdfQuerySalt()
        {
            foreach (Tuple<string, string> t in users)
            {
                string[] postData = new string[3];
                postData[0] = "3";
                postData[1] = t.Item1;
                postData[2] = t.Item2;
                ConnectionManager.SendData2("https://147.175.98.36/fetch.php", postData);
            }
        }


        static void Main(string[] args)
        {
            nacitaj();
            // naplnArgon();

            
            //naplnMD5();
            //naplnMD5S();
            //naplnPBKDF();
            // System.Net.ServicePointManager.DefaultConnectionLimit = 100;

            
            //    for(int i = 0; i < 5; i++)
            //    {
            //        var thread = new System.Threading.Thread(new System.Threading.ThreadStart(Send));
            //        thread.Start();
            //    }

            //}


            //private void Send()
            //{
            //    for (int i = 0; i < 100; i++)
            //        ConnectionManager.SendData("rnd string");
            //}
            //md5Plain();
            //argon2Plain();
            //md5sPlain();
            //pkbdfPlain();

            //argonQuerySalt();
            md5QuerySalt();
            //pbkdfQuerySalt();
            Console.ReadKey();
        }

    }
}

