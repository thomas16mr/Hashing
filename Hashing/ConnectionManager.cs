using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace Hashing
{
    class ConnectionManager
        {

        
        public ConnectionManager()
        {

        }

        //funkcia sa pouziva pri naplneni databazy a aut. cislo 1
        // klient posle reqeust na server a caka na odpoved
        public static void SendData(string URI,string data)
        {
            //pomocny timer na meranie casu
            var watch = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                WebRequest request = WebRequest.Create(URI);
                request.Method = "POST";

                //server pristupuje k nasim udaje s aliasom message
                string postData = "message=" + data;
                byte[] byteArray = Encoding.UTF8.GetBytes(postData);
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = byteArray.Length;
                 
                //vytvorime datastream a dame tam nase udaje
                Stream dataStream = request.GetRequestStream();
                dataStream.Write(byteArray, 0, byteArray.Length);
                dataStream.Close();

                //cakame na odpoved
                WebResponse response = request.GetResponse();
                request.Credentials = CredentialCache.DefaultCredentials;
                dataStream = response.GetResponseStream();
                //pripravime si reader
                StreamReader reader = new StreamReader(dataStream);
                //precitame vsetko co posiela server
                string responseFromServer = reader.ReadToEnd();  
                             
                //zastavime casovas, koniec tranzakcie
                watch.Stop();
                var time = watch.Elapsed.TotalSeconds;
                try
                {
                    lock (Program.output)
                    {
                        //zapiseme udaje do listu aby sme potom mohli pouzit
                        Program.output.Add(new Tuple<string, string>(time.ToString(), responseFromServer));
                    }
                    Console.WriteLine("Klient: " + time.ToString() + " Server:" + responseFromServer);
                }
                catch
                {
                    Console.WriteLine("Chyba, viac tredov chce pristupit k tomu istemu listu");
                    System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                    proc.Kill();
                }
                //zatvorime reader a stream
                reader.Close();
                dataStream.Close();
                response.Close();
            }
            catch
            {
                Console.WriteLine("Skontrolujte pripojenie!!!");
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                proc.Kill();
            }
          
        }

        //funkcia sa pouziva pri aut.2 
        //posle dotaz
        //prijme salt
        //hashuje a posle naspat
        public static void SendData2(string URI, string[] data)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            try
            { 
            
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            WebRequest request = WebRequest.Create(URI);
            request.Method = "POST";
            JArray array = new JArray();
            array.Add(data[0]); //index
            array.Add(data[1]); //login    

            JObject o = new JObject();
            o["MyArray"] = array;
            string json = o.ToString();

            string postData = "message=" + json;
            byte[] byteArray = Encoding.UTF8.GetBytes(postData);

            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = byteArray.Length;

            Stream dataStream = request.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();

            //Odpoved 
            WebResponse response = request.GetResponse();
            request.Credentials = CredentialCache.DefaultCredentials;
            dataStream = response.GetResponseStream();
            StreamReader reader = new StreamReader(dataStream);
            string responseFromServer = reader.ReadToEnd();
            reader.Close();
            dataStream.Close();
            response.Close();

            string[] get = new string[2];

                //hashovanie MD5
            if (data[0] == "1")
            {
                byte[] bytes = new byte[responseFromServer.Length / 2];
                for (var j = 0; j < bytes.Length; j++)
                {
                    bytes[j] = Convert.ToByte(responseFromServer.Substring(j * 2, 2), 16);
                }
                //bytes to string
                string s = Encoding.Default.GetString(bytes);
                get = MD5_hasher.GenerateHashWithSalt(data[2], s);

            }
            //hashovanie Argon2
            if (data[0] == "2")
            {
                byte[] bytes = new byte[responseFromServer.Length / 2];
                for (var j = 0; j < bytes.Length; j++)
                {
                    bytes[j] = Convert.ToByte(responseFromServer.Substring(j * 2, 2), 16);
                }
                //bytes to string
                string s = Encoding.Default.GetString(bytes);
                get = Argon2_hasher.GenerateHash(data[2], s);
            }
            //hashovanie PBKDF2
            if (data[0] == "3")
            {
                byte[] bytes = new byte[responseFromServer.Length / 2];
                for (var j = 0; j < bytes.Length; j++)
                {
                    bytes[j] = Convert.ToByte(responseFromServer.Substring(j * 2, 2), 16);
                }
                //bytes to string
                string s = Encoding.Default.GetString(bytes);
                get = PKDBF2_hasher.GenerateHash(data[2], s);
            }

            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            request = WebRequest.Create("https://147.175.98.36/justVerify.php");
            request.Method = "POST";

            array = new JArray();
            array.Add(data[0]);  //index
            array.Add(data[1]);  //login
            array.Add(get[0]);   //hash

            JObject k = new JObject();
            k["MyArray"] = array;
            string jSon = k.ToString();

            postData = "message=" + jSon;

            byteArray = Encoding.UTF8.GetBytes(postData);

            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = byteArray.Length;

            dataStream = request.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();

            //Odpoved 
            response = request.GetResponse();
            request.Credentials = CredentialCache.DefaultCredentials;      

            dataStream = response.GetResponseStream();

            reader = new StreamReader(dataStream);
            responseFromServer = reader.ReadToEnd();
            watch.Stop();
            var time = watch.Elapsed.TotalSeconds;
            try
            {
                lock (Program.output)
                {
                    Program.output.Add(new Tuple<string, string>(time.ToString(), responseFromServer));
                }
                Console.WriteLine("Klient: " + time.ToString() + " Server: " + responseFromServer);
            }
            catch
            {
                Console.WriteLine("Chyba, viac tredov chce pristupit k tomu istemu listu");
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                proc.Kill();
            }



            reader.Close();
            dataStream.Close();
            response.Close();
        }
            catch
            {
                Console.WriteLine("Skontrolujte pripojenie!!!");
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                proc.Kill();
            }

        }
    }
}
