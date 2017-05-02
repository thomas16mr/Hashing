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
        // public Listy do ktoreho ulozime dvojice meno,heslo
        // jeden list pre input a druhy pre output
        public static List<Tuple<string, string>> users = new List<Tuple<string, string>>();
        public static List<Tuple<string, string>> output = new List<Tuple<string, string>>();
        
        // Funkcia nacita dvojice meno,heslo zo suboru a ulozi ich do listu
        //ked pouzivatel zadal zlu cestu alebo subor je pouzivany inym programov
        // funkcia ohlasi chybu a vypne program
         public static void nacitaj(string path)
        {
            try
            {
                int c = 0;
                string[] lines = System.IO.File.ReadAllLines(@path);
                foreach (string s in lines)
                {
                    string[] tmp = s.Split(';');

                    users.Add(new Tuple<string, string>(tmp[0], tmp[1]));
                    c++;

                }
            }
            catch
            {
                Console.WriteLine("Chyba pri otvarani súboru!");
                Console.WriteLine("Skontrolujte cestu, alebo ci subor nie je pouzivany inou aplikaciou");
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                proc.Kill();
            }            
        }           
       
        
        // Funkcia prejde cely list dvojic meno,heslo , zahashuje heslo pomocou Argon2 a posiela request na server kde sa ulozi hash do databazy        
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
        

        public static void md5Plain(int n)
        {
             
             for(int i =0;i<n;i++)
            {
                JArray array = new JArray();
                array.Add("1");
                array.Add(users[i % 500].Item1);
                array.Add(users[i % 500].Item2);
                
                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }
        

        public static void argon2Plain(int n)
        {
            for (int i = 0; i < n; i++)
            {
                JArray array = new JArray();
                array.Add("2");
                array.Add(users[i % 500].Item1);
                array.Add(users[i % 500].Item2);

                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }

        public static void pkbdfPlain(int n)
        {
            for (int i = 0; i < n; i++)
            {
                JArray array = new JArray();
                array.Add("3");
                array.Add(users[i % 500].Item1);
                array.Add(users[i % 500].Item2);

                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }

        public static void md5QuerySalt(int n)
        {
            for (int i = 0; i < n; i++)
            {
                string[] postData = new string[3];
                postData[0] = "1";
                postData[1] = users[i % 500].Item1;
                postData[2] = users[i % 500].Item2;
                ConnectionManager.SendData2("https://147.175.98.36/fetch.php", postData);
            }
        }
        public static void argonQuerySalt(int n)
        {
            for (int i = 0; i < n; i++)
            {
               
                string[] postData = new string[3];
                postData[0] = "2";
                postData[1] = users[i % 500].Item1;
                postData[2] = users[i % 500].Item2;
                ConnectionManager.SendData2("https://147.175.98.36/fetch.php", postData);
            }
        }

        public static void pbkdfQuerySalt(int n)
        {
            for (int i = 0; i < n; i++)
            {
                string[] postData = new string[3];
                postData[0] = "3";
                postData[1] = users[i % 500].Item1;
                postData[2] = users[i % 500].Item2;
                ConnectionManager.SendData2("https://147.175.98.36/fetch.php", postData);
            }
        }

        public static void uloz()
        {
            foreach (Tuple<string, string> s in output)
            {
                using (StreamWriter writetext = File.AppendText(@"C: \Users\Tomáš Baka\Documents\Visual Studio 2015\Projects\Hashing\Hashing\write.csv"))
                {
                    writetext.WriteLine(s.Item1 + ";" + s.Item2);
                }
            }

        }

        public static void send(object n)
        {
            int nRequests = (int)n;

            md5Plain(nRequests);

            
            // argon2Plain(nRequests);
            //pkbdfPlain(nRequests);

            //md5QuerySalt(nRequests);

            //argonQuerySalt(nRequests);

           //pbkdfQuerySalt(nRequests);

        }

        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                nacitaj(args[0]);
                if(args.Length == 2)
                {
                    if(args[1] == "0")
                    {
                        if(args[2]=="1")
                        {
                            naplnMD5();
                        }
                        else if(args[2] == "2")
                        {
                            naplnArgon();
                        }
                        else if(args[2] == "3")
                        {
                            naplnPBKDF();
                        }
                        else
                        {
                            Console.WriteLine("Zle ste zadali treti parameter, takato opcia neexistuje!!");
                            System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                            proc.Kill();
                        }
                    }
                    else
                    {
                        Console.WriteLine("Druhy parameter je zly!!");
                        Console.WriteLine("Pre naplnanie databazy potrebujeme 2 parametre: cesta a cislo 0");
                        System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                        proc.Kill();
                    }                    
                }
                else if(args.Length == 5)
                {

                }
                else
                {
                    Console.WriteLine("Tato aplikacia potrebuje 2 alebo 5 parametrov!!");
                    Console.WriteLine("Skontrolujte, ci ste zadali dobre");
                }

            }
            else
            {
                Console.WriteLine("Nezadali ste ziadne validne parametre");
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                proc.Kill();
            }
            // 
            //
            //

            // Console.WriteLine(args[0]);
            int pocetTredov = 2;
            int pocetRequestov = 600;
            int n = pocetRequestov / pocetTredov;

            for (int i = 0; i < pocetTredov; i++)
            {
                var thread = new System.Threading.Thread(new ParameterizedThreadStart(send));
                thread.Start(n);
            }

            Console.ReadKey();
            uloz();

        }

    }
}

