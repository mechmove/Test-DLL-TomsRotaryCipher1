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

            // Gettysburg address
            string PlainTxt = "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battle - field of that war.We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live.It is altogether fitting and proper that we should do this.But, in a larger sense, we can not dedicate --we can not consecrate-- we can not hallow --this ground.The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract.The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced.It is rather for us to be here dedicated to the great task remaining before us-- that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion-- that we here highly resolve that these dead shall not have died in vain-- that this nation, under God, shall have a new birth of freedom-- and that government of the people, by the people, for the people, shall not perish from the earth.Abraham Lincoln November 19, 1863";
            bIn = Encoding.ASCII.GetBytes(PlainTxt);

            //int LargeNum = 100_000;
            //LargeNum = 1000;
            //string NewStr= new String('s', LargeNum);
            //bIn = Encoding.ASCII.GetBytes(NewStr);

            // for hopscotch , we need a predetermined XOR and notchplan seeds
            byte[] bSeedNotchPlan = new byte[4];
            byte[] bSeedXOR = new byte[4];

            bSeedNotchPlan[0] = 189;
            bSeedNotchPlan[1] = 80;
            bSeedNotchPlan[2] = 28;
            bSeedNotchPlan[3] = 10;

            bSeedXOR[0] = 98;
            bSeedXOR[1] = 201;
            bSeedXOR[2] = 11;
            bSeedXOR[3] = 158;

            CalculateMessageSpaceWithHopScotch(bIn, bSeedNotchPlan, bSeedXOR,3);
            //Console.ReadKey();

            //string sVeryLargeString = new String('s', 100_000_000);
            //bIn = Encoding.ASCII.GetBytes(sVeryLargeString);

            Console.Write("start time ENCODE:" + DateTime.Now + Environment.NewLine);
            // use this code to test Sequential "real-time" NotchPlan 
            TestHSModeEncode(bIn, 10);
            if (TestHSModeDecode(bIn).Equals(true))
            {
                Console.Write("Success!" + Environment.NewLine);
            } else
            {
                Console.Write("Failure!" + Environment.NewLine);
            }
            Console.Write("stop time  ENCODE:" + DateTime.Now + Environment.NewLine);
            //Console.ReadKey();

            //GenericNonStressTest(bIn);
            bIn = Encoding.ASCII.GetBytes("s");

            for (int i = 1; i <= 10; i++)
            {
                if (GenericNonStressTest(bIn).Equals(true))
                {
                    Console.Write("Run: " + i.ToString().PadLeft(3,'0') +" GenericNonStressTest: SUCCESS!" + Environment.NewLine);
                } else
                {
                    Console.Write("Run: " + i.ToString().PadLeft(3, '0') + " GenericNonStressTest: FAILURE!" + Environment.NewLine);
                }
            }

            // repeated tests for new High Security Mode code using 250_000 rotors
            int Runs = 10;
            int Failures = 0;
            int rotors = 3;
            for (int i = 1; i <= Runs; i++)
            {
                TestHSModeEncode(bIn, rotors);
                if (TestHSModeDecode(bIn).Equals(false))
                {
                    Failures++;
                }
            }
            Console.Write("There were " + Runs.ToString() + " iterations, failures = " + Failures.ToString() + Environment.NewLine);
            //Console.ReadKey();

            StressTestMaxRotors(bIn);
            TestUsingHopScotchSecureXOR(bIn);
            TestUsing1000Rotors(bIn);

            // repeated single char, 16.8MB
            Runs = 1000;
            string sRepeat = new String('s', 16_777_216);
            //string sRepeat = new String('s', 33_554_432);
            bIn = Encoding.ASCII.GetBytes(sRepeat);

            //HidingInPlainSight2_debug(bIn); // this is to test Debug Mode, extract all rotors into CSV
            //for (int i = 1; i <= Runs; i++)
            //{
            //    Console.Write("Trial:" + i + " ");
            //    HidingInPlainSight2(bIn);

            //}

            //Console.ReadKey();

            sRepeat = new String('s', 131_072);
            bIn = Encoding.ASCII.GetBytes(sRepeat);
            MessageSpacesymmetryTest(bIn);
            FatalErrorUsingUnsafeMsgSpace(bIn);

            int Large = 250_000_000;
            Large = 1_000_000;

            sRepeat = new String('s', Large);
            bIn = Encoding.ASCII.GetBytes(sRepeat);
            CalculateMessageSpaceWithHopScotch(bIn);

            Console.Write("All tests are completed, check your results and press any key to close this box" + Environment.NewLine);
            Console.ReadKey();
        }

        public static void TestHSModeEncode(byte[] bIn, int rotors)
        {
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds(); // populate regular seeds
            // ****************************************************************************************
            //oTRC.SetMovingCipherRotors(654); // define rotors here 
            //oTRC.SetMovingCipherRotors(250_000); // test run with large rotor set
            oTRC.SetMovingCipherRotors(rotors); 
            // ****************************************************************************************
            // ************** BEGIN EXTRA measures for obscuration************** 
            // Please come up with your own, don't use methods that could be known to everyone!
            byte[] inputXORdSecure = oTRC.SecureXOR(bIn, oTRC.oSeeds); // additional layer using XOR, oSeeds.SeedXOR is used to create OTP, generated by PRNG.
            // scamble some seeds
            oTRC.oSeeds.SeedRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedRotors, oTRC.oSeeds);
            oTRC.oSeeds.SeedIndividualRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedIndividualRotors, oTRC.oSeeds);
            oTRC.oSeeds.SeedNotchPlan = oTRC.SecureXOR(oTRC.oSeeds.SeedNotchPlan, oTRC.oSeeds);
            oTRC.oSeeds.SeedPlugBoard = oTRC.SecureXOR(oTRC.oSeeds.SeedPlugBoard, oTRC.oSeeds);
            oTRC.oSeeds.SeedReflector = oTRC.SecureXOR(oTRC.oSeeds.SeedReflector, oTRC.oSeeds);
            oTRC.oSeeds.SeedStartPositions = oTRC.SecureXOR(oTRC.oSeeds.SeedStartPositions, oTRC.oSeeds);
            oTRC.oSeeds.SeedTurnOverPositions = oTRC.SecureXOR(oTRC.oSeeds.SeedTurnOverPositions, oTRC.oSeeds);
            // ************** END EXTRA measures for obscuration************** 

            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                inputXORdSecure, // plaintext, already XOR'd with PRNG.
                RotaryCipherMode.NoReflector, // best security, using Reflector omits character ID. (Note, the Reflector option is included for educational and historical reasons)
                NoReflectorMode.Encipher,
                CBCMode.Forward);  // Cipher Block Chaining introduces recursion with XOR for more security. Any direction will work.

            // ************** BEGIN EXTRA measures for obscuration************** 
            // restore seeds, but this is to send false information over the internet 
            oTRC.oSeeds.SeedRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedRotors, oTRC.oSeeds);
            oTRC.oSeeds.SeedIndividualRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedIndividualRotors, oTRC.oSeeds);
            oTRC.oSeeds.SeedNotchPlan = oTRC.SecureXOR(oTRC.oSeeds.SeedNotchPlan, oTRC.oSeeds);
            oTRC.oSeeds.SeedPlugBoard = oTRC.SecureXOR(oTRC.oSeeds.SeedPlugBoard, oTRC.oSeeds);
            oTRC.oSeeds.SeedReflector = oTRC.SecureXOR(oTRC.oSeeds.SeedReflector, oTRC.oSeeds);
            oTRC.oSeeds.SeedStartPositions = oTRC.SecureXOR(oTRC.oSeeds.SeedStartPositions, oTRC.oSeeds);
            oTRC.oSeeds.SeedTurnOverPositions = oTRC.SecureXOR(oTRC.oSeeds.SeedTurnOverPositions, oTRC.oSeeds);
            // ************** END EXTRA measures for obscuration************** 

            // save all settings for Alice
            byte[] bAllSettings = oTRC.GetAll();

            File.WriteAllBytes("SettingsForAliceTestHSModeEncode.bin", bAllSettings); // Seeds and Settings are stored away
            File.WriteAllBytes("CipherTextTestHSModeEncode.bin", bCipherTxt); // save cipherText for later comparision

            oTRC = null;
        }

        public static bool TestHSModeDecode(byte[] bIn)
        {
            TomsRotaryCipher oTRC_Alice = new TomsRotaryCipher();
            // Alice loads all seeds and settings sent from Bob used to encipher the message
            oTRC_Alice.LoadAll(File.ReadAllBytes("SettingsForAliceTestHSModeEncode.bin"));

            // ************** BEGIN EXTRA measures ************** 
            // recover actual seeds
            oTRC_Alice.oSeeds.SeedRotors = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedRotors, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedIndividualRotors = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedIndividualRotors, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedNotchPlan = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedNotchPlan, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedPlugBoard = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedPlugBoard, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedReflector = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedReflector, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedStartPositions = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedStartPositions, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedTurnOverPositions = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedTurnOverPositions, oTRC_Alice.oSeeds);
            // ************** END EXTRA measures ************** 

            // TomsRotaryCipher.oSettings now contains all settings used to decipher back to plaintext.
            // GetCorrectDecodeOpt() will take inverse function required for deciphering back to plaintext
            byte[] bDecodedPlainTxt = oTRC_Alice.SAES(oTRC_Alice.oSettings.NotchPlan, File.ReadAllBytes("CipherTextTestHSModeEncode.bin"),
                oTRC_Alice.oSettings.RotaryCipherMode,
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.NoReflectorMode),
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.CBCMode));

            // ************** BEGIN EXTRA measures ************** 
            // final XOR to recover plaintext:
            byte[] bCipherTxtNew = oTRC_Alice.SecureXOR(bDecodedPlainTxt, oTRC_Alice.oSeeds);
            // ************** END EXTRA measures ************** 
            if (bCipherTxtNew.SequenceEqual(bIn))
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

        public static void HidingInPlainSight(byte[] bIn)
        {

            /* 
             * this test is used to reveal a weakness with "the Reflector".
             * 
             * Although the Germans were right about using only a single hardware configuration to encode and decode,
             * the weakness shown here is obvious, even funny. If you encrypt the letter 's' (small case) repeated 16.8 million times
             * you would expect same letter to appear at least once...... 
             * 
             */

            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds();
            oTRC.SetMovingCipherRotors(3);
            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential, 
                bIn, // plaintext, repeated 's'
                RotaryCipherMode.WithReflector, 
                NoReflectorMode.None, // direction not selectable as data must travel in both directions, speed is also compromised.
                CBCMode.None);// leave off CBC mode for this test

            string CipherTxt = Encoding.Default.GetString(bCipherTxt);
            //File.WriteAllText("test", CipherTxt);

            if (CipherTxt.IndexOf('s')<0)
            {
                Console.Write("HidingInPlainSight (with 3 rotors) : s not found [test was a SUCCESS]!" + Environment.NewLine);
            } else
            {
                Console.Write("HidingInPlainSight (with 3 rotors) : [test was a FAILURE]!" + Environment.NewLine);
            }

            /*
             * rerun same test, but this time without reflector, and see the letter 's' return.
             * (Note without Reflector, encryption is much faster, since the letter 's'
             * does not have to return in opposite direction, the process is 50% faster)
             */

            bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bIn, // plaintext, repeated 's'
                RotaryCipherMode.NoReflector,
                NoReflectorMode.Encipher,
                CBCMode.None); // leave off CBC mode for this test

            CipherTxt = Encoding.Default.GetString(bCipherTxt);

            if (CipherTxt.IndexOf('s')>0)
            {
                Console.Write("HidingInPlainSight (with 3 rotors) : s found [test was a SUCCESS]!" + Environment.NewLine);
            } else
            {
                Console.Write("HidingInPlainSight (with 3 rotors) : [test was a FAILURE]!" + Environment.NewLine);
            }

        }
        public static void HidingInPlainSight2_debug(byte[] bIn)
        {
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds();
            oTRC.SetMovingCipherRotors(3);
            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bIn, // plaintext, repeated 's'
                RotaryCipherMode.WithReflector,
                NoReflectorMode.None, // direction not selectable as data must travel in both directions, speed is also compromised.
                CBCMode.None,
                DebugMode.No);

            string CipherTxt = Encoding.Default.GetString(bCipherTxt);
            //File.WriteAllText("test", CipherTxt);

            if (CipherTxt.IndexOf('s') < 0)
            {
                Console.Write("HidingInPlainSight2 (with 3 rotors) : s not found [test was a SUCCESS]!" + Environment.NewLine);
            }
            else
            {
                Console.Write("HidingInPlainSight2 (with 3 rotors) : [test was a FAILURE]!" + Environment.NewLine);
            }

        }

        public static void HidingInPlainSight2(byte[] bIn)
        {
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds();
            oTRC.SetMovingCipherRotors(3);
            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bIn, // plaintext, repeated 's'
                RotaryCipherMode.WithReflector,
                NoReflectorMode.None, // direction not selectable as data must travel in both directions, speed is also compromised.
                CBCMode.None);// CBC mode needs to stay leave off for this test, otherwise an exception will be thrown

            string CipherTxt = Encoding.Default.GetString(bCipherTxt);
            //File.WriteAllText("test", CipherTxt);

            if (CipherTxt.IndexOf('s') < 0)
            {
                Console.Write("HidingInPlainSight2 (with 3 rotors) : s not found [test was a SUCCESS]!" + Environment.NewLine);
            }
            else
            {
                Console.Write("HidingInPlainSight2 (with 3 rotors) : [test was a FAILURE]!" + Environment.NewLine);
            }

        }
        public static void MessageSpacesymmetryTest(byte[] bIn)
        {

            /* 
             * this test is used check for expected repeating pattern if a message is twice the size of the message space.
             */

            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds();
            oTRC.SetMovingCipherRotors(2);
            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bIn, // plaintext, repeated 's'
                RotaryCipherMode.NoReflector,
                NoReflectorMode.Encipher, 
                CBCMode.None);// leave off CBC mode for this test

            Console.Write(ChkForRepeats(bCipherTxt, 100, "MessageSpacesymmetryTest"));
        }

        public static void TestUsingHopScotchSecureXOR(byte[] bIn)
        {
            /* Read all about my adventures with Sigaba-style skipping:
             * https://homeitstuff.blogspot.com/2019/10/sigaba-natural-successor-to-engima.html
             * 
             * this test uses a small number of rotors (5), but uses Sigaba style rotor skipping and an independant XOR cipher
             * Also used is Cipher Block Chaining. The security with only 5 rotors = 256^5 = 1,099,511,627,776, which is easily
             * breakable, but the other items will increase security, but difficult to calculate odds of breaking.
             * 
             * Note there are a few additional steps to enhance security, XOR scrambling Rotor seeds and the message itself. This assumes
             * the complete logic to encrypt and decrypt cannot be easily obtained, even though the DLL is available to the public.
             * 
             * Part of the challenge in any cipher scheme is secure delivery of your keys (SettingsForAlice.bin). I recommend RSA 
             * public key cryptography for this, (usage not covered here), but keep in mind any well known cipher system will be 
             * both proven and exploitable, to whatever extent this might be possible.
             * 
             */

            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds(); // generates required 32 bit words for seeding lookup tables using RNGCryptoServiceProvider
            // rotors are generated with MS' version of a PRNG: System.Random.
            oTRC.SetMovingCipherRotors(5);// HopeScotch with CBCMode and SecureXOR permits a smaller rotor definition.

            // ************** BEGIN EXTRA measures for obscuration************** 
            // Please come up with your own, don't use methods that could be known to everyone!
            byte[] inputXORdSecure = oTRC.SecureXOR(bIn, oTRC.oSeeds); // additional layer using XOR, oSeeds.SeedXOR is used to create OTP, generated by PRNG.
            // scamble some seeds
            oTRC.oSeeds.SeedRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedRotors, oTRC.oSeeds);
            oTRC.oSeeds.SeedIndividualRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedIndividualRotors, oTRC.oSeeds);
            oTRC.oSeeds.SeedNotchPlan= oTRC.SecureXOR(oTRC.oSeeds.SeedNotchPlan, oTRC.oSeeds);
            oTRC.oSeeds.SeedPlugBoard= oTRC.SecureXOR(oTRC.oSeeds.SeedPlugBoard, oTRC.oSeeds);
            oTRC.oSeeds.SeedReflector= oTRC.SecureXOR(oTRC.oSeeds.SeedReflector, oTRC.oSeeds);
            oTRC.oSeeds.SeedStartPositions= oTRC.SecureXOR(oTRC.oSeeds.SeedStartPositions, oTRC.oSeeds);
            oTRC.oSeeds.SeedTurnOverPositions= oTRC.SecureXOR(oTRC.oSeeds.SeedTurnOverPositions, oTRC.oSeeds);
            // ************** END EXTRA measures for obscuration************** 

            byte[] bCipherTxt = oTRC.SAES(NotchPlan.HopScotch, // Sigaba - style notching is the most complex, and also resource intensive.
                                                            // Hint, you may use Sequential with a larger rotor definition.
                inputXORdSecure, // plaintext, already XOR'd with PRNG.
                RotaryCipherMode.NoReflector, // best security, using Reflector omits character ID. (Note, the Reflector option is included for educational and historical reasons)
                NoReflectorMode.Encipher, 
                CBCMode.Reverse);  // Cipher Block Chaining introduces recursion with XOR for more security. Any direction will work.

            // ************** BEGIN EXTRA measures for obscuration************** 
            // restore seeds, but this is to send false information over the internet 
            oTRC.oSeeds.SeedRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedRotors, oTRC.oSeeds);
            oTRC.oSeeds.SeedIndividualRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedIndividualRotors, oTRC.oSeeds);
            oTRC.oSeeds.SeedNotchPlan = oTRC.SecureXOR(oTRC.oSeeds.SeedNotchPlan, oTRC.oSeeds);
            oTRC.oSeeds.SeedPlugBoard = oTRC.SecureXOR(oTRC.oSeeds.SeedPlugBoard, oTRC.oSeeds);
            oTRC.oSeeds.SeedReflector = oTRC.SecureXOR(oTRC.oSeeds.SeedReflector, oTRC.oSeeds);
            oTRC.oSeeds.SeedStartPositions = oTRC.SecureXOR(oTRC.oSeeds.SeedStartPositions, oTRC.oSeeds);
            oTRC.oSeeds.SeedTurnOverPositions = oTRC.SecureXOR(oTRC.oSeeds.SeedTurnOverPositions, oTRC.oSeeds);
            // ************** END EXTRA measures for obscuration************** 

            // save all settings for Alice
            byte[] bAllSettings = oTRC.GetAll();

            File.WriteAllBytes("SettingsForAlice.bin", bAllSettings); // Seeds and Settings are stored away
            oTRC = null;

            //send to Alice bCipherTxt and bAllSettings (using Alice's public key)

            // PUBLIC INTERNET SPACE.... THE WILD WILD WEST, PROTECT YOURSELF!


            // Alice receives and creates her own instance of TomsRotaryCiphr
            TomsRotaryCipher oTRC_Alice = new TomsRotaryCipher();
            // Alice loads all seeds and settings sent from Bob used to encipher the message
            oTRC_Alice.LoadAll(File.ReadAllBytes("SettingsForAlice.bin"));
            
            // ************** BEGIN EXTRA measures ************** 
            // recover actual seeds
            oTRC_Alice.oSeeds.SeedRotors = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedRotors, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedIndividualRotors = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedIndividualRotors, oTRC_Alice.oSeeds); 
            oTRC_Alice.oSeeds.SeedNotchPlan = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedNotchPlan, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedPlugBoard = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedPlugBoard, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedReflector = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedReflector, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedStartPositions = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedStartPositions, oTRC_Alice.oSeeds);
            oTRC_Alice.oSeeds.SeedTurnOverPositions = oTRC_Alice.SecureXOR(oTRC_Alice.oSeeds.SeedTurnOverPositions, oTRC_Alice.oSeeds);
            // ************** END EXTRA measures ************** 

            // TomsRotaryCipher.oSettings now contains all settings used to decipher back to plaintext.
            // GetCorrectDecodeOpt() will take inverse function required for deciphering back to plaintext
            byte[] bDecodedPlainTxt = oTRC_Alice.SAES(oTRC_Alice.oSettings.NotchPlan, bCipherTxt,
                oTRC_Alice.oSettings.RotaryCipherMode,
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.NoReflectorMode),
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.CBCMode));

            // ************** BEGIN EXTRA measures ************** 
            // final XOR to recover plaintext:
            byte[] bCipherTxtNew = oTRC_Alice.SecureXOR(bDecodedPlainTxt, oTRC_Alice.oSeeds);
            // ************** END EXTRA measures ************** 
            if (bCipherTxtNew.SequenceEqual(bIn))
            {
                //Console.Write("TestUsingHopScotchSecureXOR:" + Encoding.ASCII.GetString(bCipherTxtNew) + Environment.NewLine);
                Console.Write("TestUsingHopScotchSecureXOR : SUCCESS!" + Environment.NewLine);
            
            } else
            {
                Console.Write("TestUsingHopScotchSecureXOR : FAILURE!" + Environment.NewLine);
            }
}

        public static bool CalculateMessageSpaceWithHopScotch(byte[] bIn, byte[] bSeedNotchPlan = null, byte[] bSeedXOR = null, int Rotors = 2)
        {
            /* 
             * Test how much security does Sigaba -style skipping provides. Safe message space with 2 rotors and regular odometer 
             * skipping = 256 ^ 2 = 65_536 characters. The question what is the actual safe message space if we use 2 rotors 
             * and Sigaba skipping logic?              * 
             * 
             * The answer cannot be determined due to limitations with large numbers in c#, but this test is very revealing!
             */

            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds(); // generates required 32 bit words for seeding lookup tables using RNGCryptoServiceProvider
                                  // rotors are generated with MS' version of a PRNG: System.Random.
            if (bSeedNotchPlan != null)
            {
                oTRC.oSeeds.SeedXOR[0] = bSeedXOR[0];
                oTRC.oSeeds.SeedXOR[1] = bSeedXOR[1];
                oTRC.oSeeds.SeedXOR[2] = bSeedXOR[2];
                oTRC.oSeeds.SeedXOR[3] = bSeedXOR[3];

                oTRC.oSeeds.SeedXOR = oTRC.SecureXOR(oTRC.oSeeds.SeedXOR, oTRC.oSeeds);
            }
            if (Rotors.Equals(2))
            {
                oTRC.SetMovingCipherRotors(2);// HopScotch with smaller rotor definition.
            }
            else 
            {
                oTRC.SetMovingCipherRotors(Rotors);
            }


            // ************** BEGIN EXTRA measures for obscuration************** 
            // Please come up with your own, don't use methods that could be known to everyone!
            //byte[] inputXORdSecure = oTRC.SecureXOR(bIn, oTRC.oSeeds); // additional layer using XOR, oSeeds.SeedXOR is used to create OTP, generated by PRNG.
            // scamble some seeds
            oTRC.oSeeds.SeedRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedRotors, oTRC.oSeeds);
            oTRC.oSeeds.SeedIndividualRotors = oTRC.SecureXOR(oTRC.oSeeds.SeedIndividualRotors, oTRC.oSeeds); 

            if (bSeedNotchPlan==null)
            {
                oTRC.oSeeds.SeedNotchPlan = oTRC.SecureXOR(oTRC.oSeeds.SeedNotchPlan, oTRC.oSeeds);
            } else
            {
                oTRC.oSeeds.SeedNotchPlan[0] = bSeedNotchPlan[0];
                oTRC.oSeeds.SeedNotchPlan[1] = bSeedNotchPlan[1];
                oTRC.oSeeds.SeedNotchPlan[2] = bSeedNotchPlan[2];
                oTRC.oSeeds.SeedNotchPlan[3] = bSeedNotchPlan[3];

                oTRC.oSeeds.SeedNotchPlan = oTRC.SecureXOR(oTRC.oSeeds.SeedNotchPlan, oTRC.oSeeds);
            }

            oTRC.oSeeds.SeedPlugBoard = oTRC.SecureXOR(oTRC.oSeeds.SeedPlugBoard, oTRC.oSeeds);
            oTRC.oSeeds.SeedReflector = oTRC.SecureXOR(oTRC.oSeeds.SeedReflector, oTRC.oSeeds);
            oTRC.oSeeds.SeedStartPositions = oTRC.SecureXOR(oTRC.oSeeds.SeedStartPositions, oTRC.oSeeds);
            oTRC.oSeeds.SeedTurnOverPositions = oTRC.SecureXOR(oTRC.oSeeds.SeedTurnOverPositions, oTRC.oSeeds);
            // ************** END EXTRA measures for obscuration************** 
            
            Console.Write("start time ENCODE:" + DateTime.Now + Environment.NewLine);
                        byte[] bCipherTxt = oTRC.SAES(NotchPlan.HopScotch, // Sigaba -style notching 
                bIn, // plaintext
                RotaryCipherMode.NoReflector, 
                NoReflectorMode.Encipher, 
                CBCMode.None);
            Console.Write("stop time  ENCODE:" + DateTime.Now + Environment.NewLine);

            // check bCipherTxt for identical patterns starting from pos 0 length 100, compare to 100++ to position X.
            if (ChkForRepeats(bCipherTxt, 100, "CalculateMessageSpaceWithHopScotch").Contains("no repeats"))
            {
                double MaxTestedSafeSpace = bCipherTxt.Length / Math.Pow(256, oTRC.oSettings.MovingCipherRotors);
                double Space = MaxTestedSafeSpace * Math.Pow(256, oTRC.oSettings.MovingCipherRotors);

                Console.Write("CalculateMessageSpaceWithHopScotch (with " + Rotors.ToString() + " rotors) : [test was a SUCCESS]!" + Environment.NewLine);
                Console.Write("CalculateMessageSpaceWithHopScotch(with " + Rotors.ToString() + " rotors) X factor : [" + MaxTestedSafeSpace.ToString() + " X " + Math.Pow(256, oTRC.oSettings.MovingCipherRotors).ToString() + " = " + Space.ToString("N0") +  " characters]!" + Environment.NewLine);
            }
            else
            {
                Console.Write("CalculateMessageSpaceWithHopScotch (with " + Rotors.ToString() + " rotors) : [test was a FAILURE]!" + Environment.NewLine);
            }
            byte[] bAllSettings = oTRC.GetAll();
            File.WriteAllBytes("SettingsForAlice.bin", bAllSettings); // Seeds and Settings are stored away
                                                                      //send to Alice bCipherTxt and bAllSettings (using Alice's public key)

            // Alice receives and creates her own instance of TomsRotaryCiphr
            TomsRotaryCipher oTRC_Alice = new TomsRotaryCipher();
            // Alice loads all seeds and settings sent from Bob used to encipher the message
            oTRC_Alice.LoadAll(File.ReadAllBytes("SettingsForAlice.bin"));

            // TomsRotaryCipher.oSettings now contains all settings used to decipher back to plaintext.
            // GetCorrectDecodeOpt() will take inverse function required for deciphering back to plaintext
            Console.Write("start time DECODE:" + DateTime.Now + Environment.NewLine);
            byte[] bDecodedPlainTxt = oTRC_Alice.SAES(oTRC_Alice.oSettings.NotchPlan, bCipherTxt,
                oTRC_Alice.oSettings.RotaryCipherMode,
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.NoReflectorMode),
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.CBCMode));
            Console.Write("stop time  DECODE:" + DateTime.Now + Environment.NewLine);

            if (bDecodedPlainTxt.SequenceEqual(bIn))
            {
                //Console.Write("TestUsingMaxKeyspace:" + Encoding.ASCII.GetString(bDecodedPlainTxt) + Environment.NewLine);
                Console.Write("CalculateMessageSpaceWithHopScotch (with " + Rotors.ToString() + " rotors) : DECODE SUCCESS!" + Environment.NewLine);
                return true;
            }
            else
            {
                Console.Write("CalculateMessageSpaceWithHopScotch (with " + Rotors.ToString() + " rotors) : DECODE FAILURE!" + Environment.NewLine);
                return false;
            }
        }

        public static void TestUsing1000Rotors(byte[] bIn)
        {
            /* 
             * this test produces a keyspace of 256^1000 = 1.74e+2408, it will take a while to run.
             * 
             */
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds(); // generates required 32 bit words for seeds using RNGCryptoServiceProvider
            // rotors are generated with MS' version of a PRNG: System.Random.
            oTRC.SetMovingCipherRotors(1000); 
            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bIn, // plaintext
                RotaryCipherMode.NoReflector, // best security, using Reflector omits character ID. (Note, the Reflector option is included for educational and historical reasons)
                NoReflectorMode.Encipher, // Always encrypt going Forwards
                CBCMode.Reverse);  // Cipher Block Chaining introduces recursion with XOR for more security. Any direction will work.

            // save all settings for Alice
            byte[] bAllSettings = oTRC.GetAll();
            File.WriteAllBytes("SettingsForAlice.bin", bAllSettings); // Seeds and Settings are stored away
                                                                      //send to Alice bCipherTxt and bAllSettings (using Alice's public key)

            // PUBLIC INTERNET SPACE.... THE WILD WILD WEST, PROTECT YOURSELF!


            // Alice receives and creates her own instance of TomsRotaryCiphr
            TomsRotaryCipher oTRC_Alice = new TomsRotaryCipher();
            // Alice loads all seeds and settings sent from Bob used to encipher the message
            oTRC_Alice.LoadAll(File.ReadAllBytes("SettingsForAlice.bin"));

            // TomsRotaryCipher.oSettings now contains all settings used to decipher back to plaintext.
            // GetCorrectDecodeOpt() will take inverse function required for deciphering back to plaintext
            byte[] bDecodedPlainTxt = oTRC_Alice.SAES(oTRC_Alice.oSettings.NotchPlan, bCipherTxt,
                oTRC_Alice.oSettings.RotaryCipherMode,
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.NoReflectorMode),
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.CBCMode));

            if (bDecodedPlainTxt.SequenceEqual(bIn))
            {
                //Console.Write("TestUsingMaxKeyspace:" + Encoding.ASCII.GetString(bDecodedPlainTxt) + Environment.NewLine);
                Console.Write("TestUsing1000Rotors: SUCCESS!" + Environment.NewLine);
            } else
            {
                Console.Write("TestUsing1000Rotors: FAILURE!" + Environment.NewLine); 
            }

        }
        public static void StressTestMaxRotors(byte[] bIn)
        {
            /* 
             * this test is trying to determine how many rotors we can utilize.
             * You will need to create a small text file called “RotorsForTest.txt” 
             * in the bin\Debug folder containing number of rotors to test.
             * 
             * this is for purposes of testing the EXE on other machines and changing 
             * the number of rotors without a GUI.
             * 
             */

            //int[,] NotchTurnoverPlan = new int[1494, 356541];

            ////max size of int[,] = 532,675,562
            //int[,] NotchTurnoverPlan;
            ////NotchTurnoverPlan = new int[2, 266_337_781];
            ////NotchTurnoverPlan = new int[3, 177_558_521];
            ////NotchTurnoverPlan = new int[4, 133_168_890];

            //byte[] bNext = new byte[2_130_702_268];  
            int MaxRotorSize = (532_675_242 / bIn.Length) - 2;

            if (Convert.ToInt32(File.ReadAllText("RotorsForTest.txt")) > MaxRotorSize)
            {
                Console.Write("Reduce MaxRotorSize to " + MaxRotorSize + Environment.NewLine + "Press Enter to continue..." + MaxRotorSize + Environment.NewLine);
                Console.ReadKey();
            }

            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds(); // generates required 32 bit words for seeds using RNGCryptoServiceProvider
            // rotors are generated with MS' version of a PRNG: System.Random.
            oTRC.SetMovingCipherRotors(Convert.ToInt32(File.ReadAllText("RotorsForTest.txt")));
            Console.Write("oTRC.oSettings.MovingCipherRotors ="  + oTRC.oSettings.MovingCipherRotors + Environment.NewLine);
            Console.Write("start time ENCODE StressTestMaxRotors:" + DateTime.Now + Environment.NewLine);
            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bIn, // plaintext
                RotaryCipherMode.NoReflector, 
                NoReflectorMode.Encipher, 
                CBCMode.None);
            Console.Write("end time ENCODE StressTestMaxRotors:" + DateTime.Now + Environment.NewLine);

            // save all settings for Alice
            byte[] bAllSettings = oTRC.GetAll();
            File.WriteAllBytes("SettingsForAlice.bin", bAllSettings); // Seeds and Settings are stored away
                                                                      //send to Alice bCipherTxt and bAllSettings (using Alice's public key)

            // PUBLIC INTERNET SPACE.... THE WILD WILD WEST, PROTECT YOURSELF!


            // Alice receives and creates her own instance of TomsRotaryCiphr
            TomsRotaryCipher oTRC_Alice = new TomsRotaryCipher();
            // Alice loads all seeds and settings sent from Bob used to encipher the message
            oTRC_Alice.LoadAll(File.ReadAllBytes("SettingsForAlice.bin"));

            // TomsRotaryCipher.oSettings now contains all settings used to decipher back to plaintext.
            // GetCorrectDecodeOpt() will take inverse function required for deciphering back to plaintext
            Console.Write("start time DECODE StressTestMaxRotors:" + DateTime.Now + Environment.NewLine);
            byte[] bDecodedPlainTxt = oTRC_Alice.SAES(oTRC_Alice.oSettings.NotchPlan, bCipherTxt,
                oTRC_Alice.oSettings.RotaryCipherMode,
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.NoReflectorMode),
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.CBCMode));

            Console.Write("end time DECODE StressTestMaxRotors:" + DateTime.Now + Environment.NewLine);
            if (bDecodedPlainTxt.SequenceEqual(bIn))
            {
                //Console.Write("TestUsingMaxKeyspace:" + Encoding.ASCII.GetString(bDecodedPlainTxt) + Environment.NewLine);
                Console.Write("StressTestMaxRotors: SUCCESS!" + Environment.NewLine);
            } else
            {
                Console.Write("StressTestMaxRotors: FAILURE!" + Environment.NewLine);
            }

        }

        public static bool GenericNonStressTest(byte[] bIn)
        {
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds(); // generates required 32 bit words for seeds using RNGCryptoServiceProvider
            // rotors are generated with MS' version of a PRNG: System.Random.
            oTRC.SetMovingCipherRotors(3);
            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bIn, // plaintext
                RotaryCipherMode.WithReflector,
                NoReflectorMode.Encipher,
                CBCMode.None,
                DebugMode.Yes);

            // save all settings for Alice
            byte[] bAllSettings = oTRC.GetAll();
            File.WriteAllBytes("SettingsForAlice.bin", bAllSettings); // Seeds and Settings are stored away
                                                                      //send to Alice bCipherTxt and bAllSettings (using Alice's public key)

            // PUBLIC INTERNET SPACE.... THE WILD WILD WEST, PROTECT YOURSELF!


            // Alice receives and creates her own instance of TomsRotaryCiphr
            TomsRotaryCipher oTRC_Alice = new TomsRotaryCipher();
            // Alice loads all seeds and settings sent from Bob used to encipher the message
            oTRC_Alice.LoadAll(File.ReadAllBytes("SettingsForAlice.bin"));

            // TomsRotaryCipher.oSettings now contains all settings used to decipher back to plaintext.
            // GetCorrectDecodeOpt() will take inverse function required for deciphering back to plaintext
            byte[] bDecodedPlainTxt = oTRC_Alice.SAES(oTRC_Alice.oSettings.NotchPlan, bCipherTxt,
                oTRC_Alice.oSettings.RotaryCipherMode,
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.NoReflectorMode),
                oTRC_Alice.GetCorrectDecodeOpt(oTRC_Alice.oSettings.CBCMode));

            if (bDecodedPlainTxt.SequenceEqual(bIn))
            {
                return true;
            }
            else
            {
                return false;
            }

        }

        public static void FatalErrorUsingUnsafeMsgSpace(byte[] bIn)
        {
            /* 
             * 12/12/2024 TJW this test now passes, but is left for proof.
             * Please pay attention!
             * 
             * this test produces a faulty messagespace due to selected options 
             * In other words, there is a fatal flaw that can easily be revealed by passing a single character.
             * 
             * This does not mean a message cannot be sent with this option, it just means a pattern can be discovered 
             * if someone tries hard enough.
             * 
             */
            TomsRotaryCipher oTRC = new TomsRotaryCipher();
            oTRC.PopulateSeeds(); // generates required 32 bit words for seeds using RNGCryptoServiceProvider
            // rotors are generated with MS' version of a PRNG: System.Random.
            oTRC.SetMovingCipherRotors(2);
            byte[] bCipherTxt = oTRC.SAES(NotchPlan.Sequential,
                bIn, // plaintext
                     // the following options will result in vastly reduced message space!
                RotaryCipherMode.NoReflector, 
                NoReflectorMode.Encipher, 
                CBCMode.None);

            Console.Write(ChkForRepeats(bCipherTxt, 100, "FatalErrorUsingUnsafeMsgSpace"));
        }


        public static string ChkForRepeats(byte[] bCipherTxt, int RepeatingOffset,string functionName)
        {
            bool AnyMatch;
            Int64 Limit = bCipherTxt.Length - RepeatingOffset - 1;
            Int64 CalculatedRepeat = 0;
            for (Int64 l = 0; l < Limit; l++)
            {
                AnyMatch = DoesItMatch(bCipherTxt, 0, l + RepeatingOffset, RepeatingOffset);
                if (AnyMatch.Equals(true))
                {
                    CalculatedRepeat = l + RepeatingOffset;
                    long CipherTxtLen = bCipherTxt.Length;
                    decimal SafeMsgSpaceRatio = (Convert.ToDecimal(CalculatedRepeat) / Convert.ToDecimal(CipherTxtLen))*100;
                    return functionName + ": message space seems to repeat after position " + (CalculatedRepeat).ToString() + "." + " Safe Msg Space Ratio = " + SafeMsgSpaceRatio.ToString("0.##") + "% " + Environment.NewLine;
                }
            }
            return "no repeats!"+Environment.NewLine;
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
    }
}

