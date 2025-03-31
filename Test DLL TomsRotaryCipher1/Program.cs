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

            // First, select your tests: Sequential, HopScotch, Hiding Plain Sight. All can be selected.
            // Then select your Payload option (what will be get enciphered) : SingleLetterRepeat or Variable text.
            // Then run EncodeFirst with "true", then switch DLLs then change below from true to false and run again.
            // Or you may run with same DLL for a complete test.
            bool EncodeFirst = true; // true = Encipher, outputs will get saved, then false = Decipher will compare outputs
            bool Do_Sequential_Test = true;
            bool Do_HopScotch_Test = true;
            bool Do_HidingInPlainSightReflector_Test = true;
            int RepeatHidingInPlainSight = 1; // min value = 1
            bool Do_Extra_Tests = false; // these are independant tests, what ever you want to do
            bool Do_SingleLetterRepeat_Test = true; // if true, a single letter is used to detect "message space" or repeating patterns.
                                                    // if false, the payload will be various random characters, typical of a
                                                    // "secret message". 

            int Rotors = 3; // 256 ^ 3 = 16,777,216 message space
            //Rotors = 2; // 256 ^ 2 = 65,536 message space

            Int32 PlainTxt = 1_000_000_000; // 1 Gig Byte message, this will take a while to process.
            //PlainTxt = 500_000_000;
            PlainTxt = 33_554_432;
            PlainTxt = 131_072;

            char SingleLetterRepeatTst = (char)'z';

            DateTime StartTime;
            DateTime EndTime;

            TomsRotaryCipher oTRC = new TomsRotaryCipher();

            // be sure to define BranchName prior to compiling your DLL if you want to test different versions:
            Console.Write("DLL BranchName: " + oTRC.oSettings.BranchName + Environment.NewLine + Environment.NewLine);

            int localRotors;
            Int32 localPlainTxt;

            if (Do_Extra_Tests)
            {
                //string CipherTextOutput = "CipherTextTestHopScotchEncode.bin";
                string CipherTextOutput = "CipherTextTestHSModeEncode.bin";

                Console.Write("Analyzing FileName : " + CipherTextOutput + Environment.NewLine + Environment.NewLine);
                Console.Write("Msg length=" + File.ReadAllBytes(CipherTextOutput).Length.ToString("N0") + Environment.NewLine + Environment.NewLine);
                int LargestWordSearch = 15; // from pos 0 to LargestWordSearch, find all occurrances and relative positioning
                int SmallestWordSearch = 5; // drill down from LargestWordSearch to SmallestWordSearch
                if (File.Exists(CipherTextOutput))
                {
                    byte[] bCipherTxt = File.ReadAllBytes(CipherTextOutput);
                    for (int i = LargestWordSearch; i >= SmallestWordSearch; i--)
                    {
                        Console.Write(ChkForRepeats(bCipherTxt, i, "DoExtraTests"));
                        Console.Write(ChkForRepeats(bCipherTxt, i, "DoExtraTests", bCipherTxt.Length / 2 ));
                        Console.Write(ChkForRepeats(bCipherTxt, i, "DoExtraTests", bCipherTxt.Length / 3));
                        Console.Write(ChkForRepeats(bCipherTxt, i, "DoExtraTests", bCipherTxt.Length / 4));
                    }
                }

                Console.Write(Environment.NewLine + "Extra Tests has concluded!" + Environment.NewLine + Environment.NewLine);
                Console.ReadKey();
            }

            if (EncodeFirst)
            {   

                for (int i=1;i<= RepeatHidingInPlainSight; i++)
                {
                    // first, get a set of keys that will be used for both DLLs:
                    oTRC.PopulateSeeds(); // populate regular seeds
                    oTRC.SetMovingCipherRotors(Rotors);
                    byte[] bAllSettings = oTRC.GetAll();
                    File.WriteAllBytes("AllSettings.bin", bAllSettings);
                    if (Do_SingleLetterRepeat_Test)
                    {
                        Console.Write("Single letter Repeat Test with letter (" + SingleLetterRepeatTst + ")" + Environment.NewLine + Environment.NewLine);
                        string NewStr = new String(SingleLetterRepeatTst, PlainTxt);
                        bIn = Encoding.ASCII.GetBytes(NewStr);
                    }
                    else
                    {
                        Console.Write("Variable Pseudo-Random Payload" + Environment.NewLine + Environment.NewLine);
                        RNGCryptoServiceProvider oRNG1 = new RNGCryptoServiceProvider();
                        bIn = new byte[PlainTxt];
                        oRNG1.GetBytes(bIn);
                        oRNG1.Dispose();
                    }

                    File.WriteAllBytes("bInput.bin", bIn);

                    localRotors = oTRC.oSettings.MovingCipherRotors;
                    localPlainTxt = bIn.Length;
                    bIn = new byte[0]; // free up memory
                    bAllSettings = new byte[0]; // free up memory

                    Console.Write("For Rotors=" + localRotors.ToString("N0") + ", PlainTxt=" + localPlainTxt.ToString("N0") + Environment.NewLine + Environment.NewLine);

                    if (Do_SingleLetterRepeat_Test&& Do_HidingInPlainSightReflector_Test)
                    {
                        HidingInPlainSight("bInput.bin", "AllSettings.bin", SingleLetterRepeatTst);
                    }
                }

                if (Do_Sequential_Test)
                {
                    // now run encryption and save the output
                    StartTime = DateTime.Now;
                    Console.Write("start time Sequential ENCODE:" + StartTime + Environment.NewLine);
                    TestHSModeEncode("bInput.bin", "AllSettings.bin", "CipherTextTestHSModeEncode.bin", Do_SingleLetterRepeat_Test);
                    EndTime = DateTime.Now;
                    Console.Write("stop time Sequential ENCODE:" + EndTime + Environment.NewLine);
                    Console.Write("Time Elapsed: " + (EndTime - StartTime).TotalSeconds.ToString("0.00") + " seconds" + Environment.NewLine + Environment.NewLine);
                }

                if (Do_HopScotch_Test)
                {
                    StartTime = DateTime.Now;
                    Console.Write("start time Hopscotch ENCODE:" + StartTime + Environment.NewLine);
                    TestHopScotchEncode("bInput.bin", "AllSettings.bin", "CipherTextTestHopScotchEncode.bin", Do_SingleLetterRepeat_Test);
                    EndTime = DateTime.Now;
                    Console.Write("stop time Hopscotch ENCODE:" + EndTime + Environment.NewLine);
                    Console.Write("Time Elapsed: " + (EndTime - StartTime).TotalSeconds.ToString("0.00") + " seconds" + Environment.NewLine + Environment.NewLine);
                }
            }
            else
            {
                oTRC.LoadAll(File.ReadAllBytes("AllSettings.bin"));

                localRotors = oTRC.oSettings.MovingCipherRotors;
                localPlainTxt = File.ReadAllBytes("bInput.bin").Length;

                Console.Write("For Rotors=" + localRotors.ToString("N0") + ", PlainTxt=" + localPlainTxt.ToString("N0") + Environment.NewLine + Environment.NewLine);

                if (Do_Sequential_Test)
                {
                    // now run Decryption and compare the output
                    StartTime = DateTime.Now;
                    Console.Write("start time Sequential DECODE:" + StartTime + Environment.NewLine);
                    TestHSModeDecode("bInput.bin", "AllSettings.bin", "CipherTextTestHSModeEncode.bin");
                    EndTime = DateTime.Now;
                    Console.Write("stop time Sequential DECODE:" + EndTime + Environment.NewLine);
                    Console.Write("Time Elapsed: " + (EndTime - StartTime).TotalSeconds.ToString("0.00") + " seconds" + Environment.NewLine + Environment.NewLine);
                }

                if (Do_HopScotch_Test)
                {
                    StartTime = DateTime.Now;
                    Console.Write("start time Hopscotch DECODE:" + StartTime + Environment.NewLine);
                    TestHopScotchDecode("bInput.bin", "AllSettings.bin", "CipherTextTestHopScotchEncode.bin");
                    EndTime = DateTime.Now;
                    Console.Write("stop time Hopscotch DECODE:" + EndTime + Environment.NewLine);
                    Console.Write("Time Elapsed: " + (EndTime - StartTime).TotalSeconds.ToString("0.00") + " seconds" + Environment.NewLine + Environment.NewLine);
                }
            }
            oTRC = null;
            Console.Write("All tests are completed, check your results and press any key to close this box" + Environment.NewLine);
            Console.ReadKey();
        }

        public static void TestHSModeEncode(string input, string settings, string sCipherTxt, bool bSingleLetterRepeat_Test = false)
        {
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.LoadAll(File.ReadAllBytes(settings));

            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                File.ReadAllBytes(input),
                RotaryCipherMode.NoReflector, // best security, using Reflector omits character ID. (Note, the Reflector option is included for educational and historical reasons)
                NoReflectorMode.Encipher,
                CBCMode.None,// Cipher Block Chaining introduces recursion with XOR for more security. If Yes, any direction will work.
                DebugMode.No);

            File.WriteAllBytes(sCipherTxt, bCipherTxt); // save cipherText for later comparision

            if (bSingleLetterRepeat_Test)
            {
                Console.Write(ChkForRepeats(bCipherTxt, 100, "TestHSModeEncode"));
            }

            oTRC = null;
        }
        public static bool TestHSModeDecode(string input, string settings, string sCipherTxt)
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
                CBCMode.None,
                DebugMode.No);

            oTRC_Alice = null;

            if (bDecodedPlainTxt.SequenceEqual(File.ReadAllBytes(input)))
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

        public static void TestHopScotchEncode(string input, string settings, string sCipherTxt, bool bSingleLetterRepeat_Test = false)
        {
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.LoadAll(File.ReadAllBytes(settings));

            byte[] bCipherTxt = oTRC.SAES(NotchPlan.HopScotch,
                File.ReadAllBytes(input),
                RotaryCipherMode.NoReflector, // best security, using Reflector omits character ID. (Note, the Reflector option is included for educational and historical reasons)
                NoReflectorMode.Encipher,
                CBCMode.None); 

            if (bSingleLetterRepeat_Test)
            {
                Console.Write(ChkForRepeats(bCipherTxt, 100, "TestHopScotchEncode"));
            }

            File.WriteAllBytes(sCipherTxt, bCipherTxt); // save cipherText for later comparision

            oTRC = null;
        }
        public static bool TestHopScotchDecode(string input, string settings, string sCipherTxt)
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
                CBCMode.None);

            oTRC_Alice = null;

            if (bDecodedPlainTxt.SequenceEqual(File.ReadAllBytes(input)))
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

        public static string ChkForRepeats(byte[] bCipherTxtSource, int RepeatingOffset, string functionName, Int64 StartSearch= 0)
        {
            byte[] bCipherTxt = new byte[bCipherTxtSource.Length];

            if (StartSearch.Equals(0))
            {
                Array.Copy(bCipherTxtSource, bCipherTxt, bCipherTxtSource.Length);
            } 
            else
            {
                Array.Copy(bCipherTxtSource,0, bCipherTxt, StartSearch, StartSearch);
                Array.Copy(bCipherTxtSource, StartSearch, bCipherTxt, 0, StartSearch);
            }

            //File.WriteAllBytes("CipherTxtDeckCut.bin", bCipherTxt); // this is for debugging using Hex Editor Neo

            bCipherTxtSource = null;

            string RepeatStrRtn = string.Empty;
            string NoRepeatStr = functionName + ", " + RepeatingOffset.ToString() + " char block sizes, deck cut at " + StartSearch.ToString("N0") +  " there were NO Repeats." + Environment.NewLine;
            bool FoundRepeat = false;
            Int64 Limit = bCipherTxt.Length - RepeatingOffset - 1;
            Int64 CalculatedRepeat = 0;
            for (Int64 l = 0; l < Limit; l++)
            {
                if (DoesItMatch(bCipherTxt, 0, l + RepeatingOffset, RepeatingOffset).Equals(true))
                {
                    CalculatedRepeat = l + RepeatingOffset;
                    long CipherTxtLen = bCipherTxt.Length;
                    decimal SafeMsgSpaceRatio = (Convert.ToDecimal(CalculatedRepeat) / Convert.ToDecimal(CipherTxtLen)) * 100;
                    RepeatStrRtn += functionName + ", " + RepeatingOffset.ToString() + " char block sizes, deck cut at " + StartSearch.ToString("N0") +  " pattern starting at pos. " + (CalculatedRepeat).ToString("N0") + ", Msg Space Ratio = " + SafeMsgSpaceRatio.ToString("0.##") + "%" + Environment.NewLine;
                    FoundRepeat = true;
                }
            }

            bCipherTxt = null;

            if (FoundRepeat.Equals(false))
            {
                return NoRepeatStr;
            }
            else
            {
                return RepeatStrRtn;
            }
        }
        public static Boolean DoesItMatch(byte[] bIn, long start, long FindAt, int length)
        {
            for (int i = 0; i <= length - 1; i++)
            {
                if (!bIn[start].Equals(bIn[FindAt]))
                {
                    return false;
                }
                ++start;
                ++FindAt;
            }
            return true;
        }
        public static void HidingInPlainSight(string input, string settings, char SingleLtr)
        {

            /* 
             * this test is used to reveal a weakness with "the Reflector".
             * 
             * Although the Germans were right about using only a single hardware configuration to encode and decode,
             * the weakness shown here is obvious, even funny. If you encrypt a letter repeated 16.8 million times
             * you would expect same letter to appear at least once...... 
             * 
             */

            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.LoadAll(File.ReadAllBytes(settings));
            int localRotors = oTRC.oSettings.MovingCipherRotors;
            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                File.ReadAllBytes(input), // plaintext, repeated SingleLtr
                RotaryCipherMode.WithReflector,
                NoReflectorMode.None, // direction not selectable as data must travel in both directions, speed is also compromised.
                CBCMode.None,// leave off CBC mode for this test
                DebugMode.No);

            if (FindLtr(bCipherTxt, SingleLtr).Equals(0))
            {
                Console.Write("HidingInPlainSight (with " + localRotors.ToString() + " rotors) : " + SingleLtr + " not found [test was a SUCCESS]!" + Environment.NewLine);
            }
            else
            {
                Console.Write("HidingInPlainSight (with " + localRotors.ToString() + " rotors) : [test was a FAILURE]!" + Environment.NewLine);
            }

            /*
             * run a DECODE test to make sure it matches source
             */

            bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bCipherTxt, // plaintext, repeated SingleLtr
                RotaryCipherMode.WithReflector,
                NoReflectorMode.None, // direction not selectable as data must travel in both directions, speed is also compromised.
                CBCMode.None,// leave off CBC mode for this test
                DebugMode.No);

            if (File.ReadAllBytes(input).SequenceEqual(bCipherTxt))
            {
                Console.Write("HidingInPlainSight (with " + localRotors.ToString() + " rotors) : " + SingleLtr + " [DECODE test was a SUCCESS]!" + Environment.NewLine);
            }
            else
            {
                Console.Write("HidingInPlainSight (with " + localRotors.ToString() + " rotors) : " + SingleLtr + " [DECODE test was a FAILURE]!" + Environment.NewLine);
            }

            /*
             * rerun same test, but this time without reflector, and see the letter 'z' return.
             * (Note without Reflector, encryption is much faster, since the letter 'z'
             * does not have to return in opposite direction, the process is 50% faster)
             */

            bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                File.ReadAllBytes(input), // plaintext, repeated letter
                RotaryCipherMode.NoReflector,
                NoReflectorMode.Encipher,
                CBCMode.None,// leave off CBC mode for this test
                DebugMode.No);

            if (FindLtr(bCipherTxt, SingleLtr).Equals((char)SingleLtr))
            {
                Console.Write("HidingInPlainSight (with " + localRotors.ToString() + " rotors) : " + SingleLtr + " found [test was a SUCCESS]!" + Environment.NewLine + Environment.NewLine);
            }
            else
            {
                Console.Write("HidingInPlainSight (with " + localRotors.ToString() + " rotors) : " + SingleLtr + " NOT found [test was inconclusive]!" + Environment.NewLine + Environment.NewLine);

            }

            bCipherTxt = new byte[0]; // free up memory

            oTRC = null;
        }

        private static int FindLtr (byte[] bCipherTxt, char SingleLtr)
        {
            return bCipherTxt.Distinct().ToArray().Where(x => x == SingleLtr).FirstOrDefault();
        }
    }
}

