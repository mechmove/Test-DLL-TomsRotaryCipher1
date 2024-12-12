using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace registration
{
    public class registerApp
    {
        public static void register(string AppNameToAuthenticate, int Access, string signature)
        {
            string AppNamelogFileForUSBDrive = "AppPass.log";
            string USBDrive = "C:\\USB Drive\\" + AppNamelogFileForUSBDrive;

            string saltToStoreUSBDrive = Guid.NewGuid().ToString(); // this is generated IF its the first record, otherwise salt = last hash for proper blockchaining
            string hash = Hashing.sha256.ComputeSha256Hash(signature + saltToStoreUSBDrive + AppNameToAuthenticate + Access.ToString());

            

            System.IO.FileStream fs;
            byte[] bytes;

            // first check to see if access level is correct, no need to add another log entry
            bool CurrentStatus = DoesMyProgHaveAccess(AppNameToAuthenticate, signature);
            if (CurrentStatus.Equals(true) && Access.Equals(1))
            {
                return;
            }
            if (CurrentStatus.Equals(false) && Access.Equals(0))
            {
                return;
            }

            if (!System.IO.File.Exists(USBDrive))
            {
                fs = System.IO.File.OpenWrite(USBDrive);
                bytes = Encoding.ASCII.GetBytes(hash + "," + saltToStoreUSBDrive);
                fs.Write(bytes);
                fs.Close();
            }
            else
            {
                IEnumerable<string> GetLastLine = System.IO.File.ReadLines(USBDrive);
                string LastLine = string.Empty;
                foreach (var vrLine in GetLastLine)
                {
                    LastLine = vrLine;
                }
                string LastComputedhash = Hashing.sha256.ComputeSha256Hash(LastLine);
                LastComputedhash = Hashing.sha256.ComputeSha256Hash(signature + LastComputedhash + AppNameToAuthenticate + Access.ToString());
                // this is stored on USB drive with salt (this contains app name in plaintext)
                System.IO.File.AppendAllText(USBDrive, Environment.NewLine + LastComputedhash);
            }

        }
        public static bool DoesMyProgHaveAccess(string AppNameToAuthenticate, string signature)
        {
            RSACryptoServiceProvider rsa = new();
            string AppNamelogFileForUSBDrive = "AppPass.log";
            string USBDrive = "C:\\USB Drive\\" + AppNamelogFileForUSBDrive;
            string Hash;
            string Salt;
            int Rtn;

            if (!File.Exists(USBDrive))
            { return false; }

            string[] GetLastLine = File.ReadLines(USBDrive).ToArray();
            int TotalLines = GetLastLine.Count() - 1;

            for (int i = TotalLines; i >= 0; i--) // this file is read backwards, last entries are most relevant
            {
                string currentLine = GetLastLine[i];

                if (currentLine.Contains(",")) // first line, with Salt
                {
                    Hash = currentLine.Substring(0, currentLine.IndexOf(','));
                    Salt = currentLine.Substring(currentLine.IndexOf(',') + 1);
                    Rtn = Compare(signature, Salt, AppNameToAuthenticate, Hash);

                }
                else
                {
                    Hash = currentLine;
                    Salt = Hashing.sha256.ComputeSha256Hash(GetLastLine[i - 1]);
                    Rtn = Compare(signature, Salt, AppNameToAuthenticate, Hash);

                }
                // One of the hash words will answer the question, does my prog have access...
                if (Rtn.Equals(1))
                { return true; }

                if (Rtn.Equals(0))
                { return false; }
            }
            return false; // if something changed, or there is neither a Yes or No answer, do not grant access!
        }

        public static int Compare(string signature, string Salt, string AppNameToAuthenticate, string Hash)
        {
            int Access = 1; // 1 to grant, 0 to revoke
            int Revoke = 0; // 1 to grant, 0 to revoke

            string RecomputedHashAccess = Hashing.sha256.ComputeSha256Hash(signature + Salt + AppNameToAuthenticate + Access.ToString());
            string RecomputedHashRevoke = Hashing.sha256.ComputeSha256Hash(signature + Salt + AppNameToAuthenticate + Revoke.ToString());
            if (RecomputedHashAccess.Equals(Hash))
            {// App has access!
                return 1;
            }
            if (RecomputedHashRevoke.Equals(Hash))
            {// App does NOT have access!
                return 0;
            }
            return -1;
        }


    }
}
