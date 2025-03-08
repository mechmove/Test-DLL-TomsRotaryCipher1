using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using StoneAgeEncryptionService;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.Remoting.Channels;
using System.Security.Cryptography;
using System.Threading;
using static StoneAgeEncryptionService.TomsRotaryCipher;
using System.Runtime;

//Trademark Notices/Disclaimer:

//TomsRotaryCipher is a c# encryption/decryption DLL that belongs to namespace StoneAgeEncryptionService.
//The source code is offered in GitHub under the MIT license. There are no guarantees the compiled DLL will
//perform per specification or to anyone's expectations. 

//Sigaba (Trademarked) was the original rotor skipping hardware of the 1950s comprising of index and control
//rotors that facilitated a pseudo random skipping pattern of the primary cipher rotors. This idea serves as
//inspiration for HopScotch, which is done in software, and may not be an accurate representation of the
//original hardware implementation. There is no association, professional or otherwise, between Sigaba and HopScotch.

//The German Enigma (Trademarked), was a commercially made encryption machine invented by German engineer
//Arthur Scherbius in the late-1910s. This machine serves as inspiration for TomsRotaryCipher, which is done in software,
//and may not be an accurate representation of the original hardware implementation. There is no association,
//professional or otherwise, between Enigma and TomsRotaryCipher.

namespace Test_DLL_TomsRotaryCipher
{
    class Program
    {
        static void Main(string[] args)
        {
            /*
             * This is a demo of how to use StoneAgeEncryptionService. Make sure you understand basic concepts and how
             * to pass in parms. StoneAgeEncryptionService is based on the famous electro-mechanical Enigma machine, but 
             * with added features, like unlimited rotors (within reason), the ability to remove the reflector, 
             * bidirectional data flow, and various skipping routines. And an unrelated but easy to use XOR stream 
             * (the Vernam cipher). A modern day concept of Cipher Block Chaining (CBC) is also implemented which introduces 
             * the power of recursion with XOR. 
             * 
             * Programming StoneAgeEncryptionService is based on byte arrays. IO will always be a byte array. 
             * Since input is text-based English, first step is conversion to byte array. Each "rotor" consists of 
             * 256 slots with a unique number from 0 to 255, stored as a byte array. "Seeds" for Rotors, start, turnover and 
             * other initialization parameters are defined by cryptographically strong 32-bit random numbers. The combination
             * of all "Seeds" and encryption options define the total strength.
             *              * 
             * Please understand StoneAgeEncryptionService is for educational and entertainment purposes. Do not use without a 
             * complete understanding of the risk you might be taking with your data. StoneAgeEncryptionService has been tested 
             * by the author, and should offer some level of security, but there are other more robust encryption methods that 
             * are virtually unbreakable. I do believe with proper usage, StoneAgeEncryptionService can be used with other 
             * available tools, but do your own testing to prove it out for yourself. 
             * 
             * For security profile of StoneAgeEncryptionService, please refer to document "True security of TomsRotaryCipher during 
             * a bruteforce attack.doc" which is a part of this project.
             * 
             * You should use more than one cipher method!
             * 
             * Below are various tests, put a breakpoint on each of them and proceed to look at code.
             * */

            byte[] bIn;
            // these tests are to check that different versions of TomsRotaryCipher produce the same result
            // after "optimization" logic.

            // First, run with "true", then switch DLLs then change below from true to false and run again.
            bool Part_I_Of_Test = false;
            bool Do_HopScotch_Test = true;

            int Rotors = 4;
            Int32 PlainTxt = 50_000_000; 
            //Int32 PlainTxt = 1_677_000_000; // largest number on my machine

            DateTime StartTime;
            DateTime EndTime;

            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            if (Part_I_Of_Test)
            {   // first, get a set of keys that will be used for both DLLs:
                oTRC.PopulateSeeds(); // populate regular seeds
                oTRC.SetMovingCipherRotors(Rotors);
                byte[] bAllSettings = oTRC.GetAll();
                File.WriteAllBytes("AllSettings.bin", bAllSettings);
                RNGCryptoServiceProvider oRNG1 = new RNGCryptoServiceProvider();
                bIn = new byte[PlainTxt];
                oRNG1.GetBytes(bIn);
                oRNG1.Dispose();
                File.WriteAllBytes("bInput.bin", bIn);
                
                Console.Write("For Rotors=" + Rotors.ToString("N0") + ", PlainTxt=" + PlainTxt.ToString("N0") + Environment.NewLine + Environment.NewLine);

                // now run encryption and save the output
                StartTime = DateTime.Now;
                Console.Write("start time Sequential ENCODE:" + StartTime + Environment.NewLine);
                TestHSModeEncode(bIn, Rotors, "AllSettings.bin", "CipherTextTestHSModeEncode.bin");
                EndTime = DateTime.Now;
                Console.Write("stop time Sequential ENCODE:" + EndTime + Environment.NewLine);
                Console.Write("Time Elapsed: " + (EndTime - StartTime).TotalSeconds.ToString("0.00") + " seconds" + Environment.NewLine + Environment.NewLine);

                if (Do_HopScotch_Test)
                {
                    StartTime = DateTime.Now;
                    Console.Write("start time Hopscotch ENCODE:" + StartTime + Environment.NewLine);
                    TestHopScotchEncode(bIn, "AllSettings.bin", "CipherTextTestHopScotchEncode.bin");
                    EndTime = DateTime.Now;
                    Console.Write("stop time Hopscotch ENCODE:" + EndTime + Environment.NewLine);
                    Console.Write("Time Elapsed: " + (EndTime - StartTime).TotalSeconds.ToString("0.00") + " seconds" + Environment.NewLine + Environment.NewLine);
                }
            }
            else
            {
                oTRC.LoadAll(File.ReadAllBytes("AllSettings.bin"));
                bIn = File.ReadAllBytes("bInput.bin");

                Console.Write("For Rotors=" + Rotors.ToString("N0") + ", PlainTxt=" + PlainTxt.ToString("N0") + Environment.NewLine + Environment.NewLine);

                // now run Decryption and compare the output
                StartTime = DateTime.Now;
                Console.Write("start time Sequential DECODE:" + StartTime + Environment.NewLine);
                TestHSModeDecode(bIn, Rotors, "AllSettings.bin", "CipherTextTestHSModeEncode.bin").Equals(true);
                EndTime = DateTime.Now;
                Console.Write("stop time Sequential DECODE:" + EndTime + Environment.NewLine);
                Console.Write("Time Elapsed: " + (EndTime - StartTime).TotalSeconds.ToString("0.00") + " seconds" + Environment.NewLine + Environment.NewLine);
                if (Do_HopScotch_Test)
                {
                    StartTime = DateTime.Now;
                    Console.Write("start time Hopscotch DECODE:" + StartTime + Environment.NewLine);
                    TestHopScotchDecode(bIn, "AllSettings.bin", "CipherTextTestHopScotchEncode.bin").Equals(true);
                    EndTime = DateTime.Now;
                    Console.Write("stop time Hopscotch DECODE:" + EndTime + Environment.NewLine);
                    Console.Write("Time Elapsed: " + (EndTime - StartTime).TotalSeconds.ToString("0.00") + " seconds" + Environment.NewLine + Environment.NewLine);
                }
            }

            Console.Write("All tests are completed, check your results and press any key to close this box" + Environment.NewLine);
            Console.ReadKey();
        }

        public static void TestHSModeEncode(byte[] bIn, int rotors, string settings, string sCipherTxt)
        {
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.LoadAll(File.ReadAllBytes(settings));

            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bIn,
                RotaryCipherMode.NoReflector, // best security, using Reflector omits character ID. (Note, the Reflector option is included for educational and historical reasons)
                NoReflectorMode.Encipher,
                CBCMode.Forward);  // Cipher Block Chaining introduces recursion with XOR for more security. Any direction will work.

            File.WriteAllBytes(sCipherTxt, bCipherTxt); // save cipherText for later comparision

            oTRC = null;
        }
        public static bool TestHSModeDecode(byte[] bIn, int rotors, string settings, string sCipherTxt)
        {
            TomsRotaryCipher oTRC_Alice = new TomsRotaryCipher();
            oTRC_Alice.LoadAll(File.ReadAllBytes(settings));

            // TomsRotaryCipher.oSettings now contains all settings used to decipher back to plaintext.
            // GetCorrectDecodeOpt() will take inverse function required for deciphering back to plaintext
            byte[] bDecodedPlainTxt = oTRC_Alice.SAES(
                NotchPlan.Sequential,
                File.ReadAllBytes(sCipherTxt),
                RotaryCipherMode.NoReflector,
                NoReflectorMode.Decipher,
                CBCMode.Reverse);

            if (bDecodedPlainTxt.SequenceEqual(bIn))
            {
                Console.Write("TestHSModeDecode : SUCCESS!" + Environment.NewLine);
                return true;
            }
            else
            {
                Console.Write("TestHSModeDecode : FAILURE!" + Environment.NewLine);
                return false;
            }
        }

        public static void TestHopScotchEncode(byte[] bIn, string settings, string sCipherTxt)
        {
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.LoadAll(File.ReadAllBytes(settings));

            byte[] bCipherTxt = oTRC.SAES(NotchPlan.HopScotch,
                bIn,
                RotaryCipherMode.NoReflector, // best security, using Reflector omits character ID. (Note, the Reflector option is included for educational and historical reasons)
                NoReflectorMode.Encipher,
                CBCMode.Forward);  // Cipher Block Chaining introduces recursion with XOR for more security. Any direction will work.

            File.WriteAllBytes(sCipherTxt, bCipherTxt); // save cipherText for later comparision

            oTRC = null;
        }
        public static bool TestHopScotchDecode(byte[] bIn, string settings, string sCipherTxt)
        {
            TomsRotaryCipher oTRC_Alice = new TomsRotaryCipher();
            oTRC_Alice.LoadAll(File.ReadAllBytes(settings));

            // TomsRotaryCipher.oSettings now contains all settings used to decipher back to plaintext.
            // GetCorrectDecodeOpt() will take inverse function required for deciphering back to plaintext
            byte[] bDecodedPlainTxt = oTRC_Alice.SAES(
                NotchPlan.HopScotch,
                File.ReadAllBytes(sCipherTxt),
                RotaryCipherMode.NoReflector,
                NoReflectorMode.Decipher,
                CBCMode.Reverse);

            if (bDecodedPlainTxt.SequenceEqual(bIn))
            {
                Console.Write("TestHopScotchDecode : SUCCESS!" + Environment.NewLine);
                return true;
            }
            else
            {
                Console.Write("TestHopScotchDecode : FAILURE!" + Environment.NewLine);
                return false;
            }
        }

    }
}

