using System;
using Yubico.YubiKey;
using CommandLine;
using System.Collections.Generic;
using System.Linq;
using Yubico.YubiKey.Piv;
using Yubico.YubiKey.Piv.Commands;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Yubico_Smart_Card_CLI_tool
{
    
    class YKSmartCardCLI
    {
        [Verb("reset", HelpText = "Reset YubiKey PIV module to factory settings.")]
        class ResetOptions
        {
            //clone options here
        }

        [Verb("change-management-key", HelpText = "Change YubiKey PIV ManagementKey from default to driver required value.")]
        class ChangeManagementKeyOptions
        {
        
             [Option('d', "default", SetName = "changeKey", HelpText ="Changes ManagementKey from YubiKey default value")]
             public bool DefaultKey { get; set; }

            [Option('r', "random", SetName = "changeKey", HelpText ="Changes Management Key from a random value")]
            public bool RandomKey { get; set; }       
            
        }
        [Verb("change-pin", HelpText = "Change YubiKey PIN from old value to new value.")]
        class ChangePinOptions
        {
            [Option('o', "old PIN", Required = true)]
            public string OldPIN { get; set; }

            [Option('n', "new PIN", Required = true)]
            public string NewPIN { get; set; }
        }

        [Verb("change-puk", HelpText = "Change YubiKey PUK from old value to new value.")]
        class ChangePukOptions
        {
            [Option('o', "old PUK", Required = true)]
            public string OldPUK { get; set; }

            [Option('n', "new PUK", Required = true)]
            public string NewPUK { get; set; }
        }
        
        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        static int Main(string[] args) =>
  Parser.Default.ParseArguments<ResetOptions, ChangeManagementKeyOptions, ChangePinOptions, ChangePukOptions>(args)
    .MapResult(
      (ResetOptions options) => RunResetAndReturnExitCode(options),
      (ChangeManagementKeyOptions options) => RunChangeManagementKeyAndReturnExitCode(options),
      (ChangePinOptions options) => RunChangePinReturnExitCode(options),
      (ChangePukOptions options) => RunChangePukReturnExitCode(options),
      errors => 1);

        static int RunResetAndReturnExitCode(ResetOptions opts)
        {
            IYubiKeyDevice yubiKey = ChooseYubiKey();

            // Reset YubiKey PIV 
            using (var piv = new PivSession(yubiKey))
            {
                piv.ResetApplication();
            }

            Console.WriteLine("YubiKey reset to factory settings");
            return 0;
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        static int RunChangeManagementKeyAndReturnExitCode(ChangeManagementKeyOptions opts)
        {
            IYubiKeyDevice yubiKey = ChooseYubiKey();

            using (var piv = new PivSession(yubiKey))
            {
                IYubiKeyConnection connection = piv.Connection;

                byte[] currentManagementKey = 
                    {
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
                    };

                if (opts.DefaultKey)
                {
                    byte[] defmgmtKey =
                    {
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
                    };
                    currentManagementKey = defmgmtKey;

                }
                else if (opts.RandomKey)
                {
                    RegistryKey akey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\charismathics\smart security interface\3bf81300008131fe15597562696b657934d4");
                    string mkey = (string)akey.GetValue(@"PIV_3DES_KEY");
                    byte[] mgmtKey = Convert.FromHexString(mkey);
                    currentManagementKey = mgmtKey;
                }

                //Authenticate with the current management key

                InitializeAuthenticateManagementKeyCommand initCmd = new(false);
                InitializeAuthenticateManagementKeyResponse initResp = connection.SendCommand(initCmd);
                if (initResp.Status != ResponseStatus.Success)
                {
                    Console.WriteLine("Initialize Management Key Authentication failed");
                }

                CompleteAuthenticateManagementKeyCommand compCmd = new(initResp, currentManagementKey);
                CompleteAuthenticateManagementKeyResponse compResp = connection.SendCommand(compCmd);
                if (compResp.Status == ResponseStatus.AuthenticationRequired)
                {
                    AuthenticateManagementKeyResult authResult = compResp.GetData();
                    Console.WriteLine("Error: " + compResp.StatusMessage);
                }
                else if (compResp.Status != ResponseStatus.Success)
                {
                    Console.WriteLine("Complete Management Key Authentication failed");
                }

                // change to a new random management key and save to the registry
                // located in [HKEY_LOCAL_MACHINE\SOFTWARE\charismathics\smart security interface\3bf81300008131fe15597562696b657934d4]
                // under "PIV_3DES_KEY"


                //generate random Management Key
                string newkey = RandomString(48);
                byte[] newMgmntKey = Convert.FromHexString(newkey);

                // save Management key value to the registry (for both YubiKey4 and YubiKey 5)
                
                // first we save it for YubiKey 4
                RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\charismathics\smart security interface\3bf81300008131fe15597562696b657934d4",true);
                key.SetValue(@"PIV_3DES_KEY", newkey, RegistryValueKind.String);
          

                // then we save it for YubiKey 5
                RegistryKey YK5key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\charismathics\smart security interface\3bfd1300008131fe158073c021c057597562694b657940", true);
                YK5key.SetValue(@"PIV_3DES_KEY", newkey, RegistryValueKind.String);
              

                // set new random management key in the YubiKey
                SetManagementKeyCommand setManagementKeyCommand = new(newMgmntKey);
                SetManagementKeyResponse setManagementKeyResponse = connection.SendCommand(setManagementKeyCommand);

                if (setManagementKeyResponse.Status != ResponseStatus.Success)
                {
                    Console.WriteLine("Change Management Key failed");
                }
                else
                    Console.WriteLine("Change Management Key successfully completed");

                CryptographicOperations.ZeroMemory(newMgmntKey);
            }

            
            return 0;
        }

        static int RunChangePinReturnExitCode(ChangePinOptions opts)
        {
            // Read old pin, new pin strings from command options
            string oldStr = opts.OldPIN;
            string newStr = opts.NewPIN;

            //Authenticate the PIN
            IYubiKeyDevice yubiKey = ChooseYubiKey();

            using (var piv = new PivSession(yubiKey))
            {

                IYubiKeyConnection connection = piv.Connection;

                byte[] oldPIN = Encoding.ASCII.GetBytes(oldStr);

                VerifyPinCommand verifyPinCommand = new(oldPIN);
                VerifyPinResponse verifyPinResponse = connection.SendCommand(verifyPinCommand);
                if (verifyPinResponse.Status != ResponseStatus.Success)
                {
                    Console.WriteLine("Verify old PIN failed");
                }

                // Change PIN
                byte[] newPIN = Encoding.ASCII.GetBytes(newStr);

                var changeReferenceDataCommand = new ChangeReferenceDataCommand(PivSlot.Pin, oldPIN, newPIN);
                ChangeReferenceDataResponse changeReferenceDataResponse = connection.SendCommand(changeReferenceDataCommand);

                if (changeReferenceDataResponse.Status != ResponseStatus.Success)
                {
                    Console.WriteLine("Change PIN failed");
                }

                CryptographicOperations.ZeroMemory(oldPIN);
                CryptographicOperations.ZeroMemory(newPIN);
            }

            Console.WriteLine("Changed PIN successfully");
            return 0;
        }

        static int RunChangePukReturnExitCode(ChangePukOptions opts)
        {
            // Read old pin, new pin strings from command options
            string oldStr = opts.OldPUK;
            string newStr = opts.NewPUK;

            //Authenticate the PIN
            IYubiKeyDevice yubiKey = ChooseYubiKey();

            using (var piv = new PivSession(yubiKey))
            {

                IYubiKeyConnection connection = piv.Connection;

                byte[] oldPUK = Encoding.ASCII.GetBytes(oldStr);

                /*
                VerifyPinCommand verifyPinCommand = new(oldPIN);
                VerifyPinResponse verifyPinResponse = connection.SendCommand(verifyPinCommand);
                if (verifyPinResponse.Status != ResponseStatus.Success)
                {
                    Console.WriteLine("Verify old PIN failed");
                }
                */

                // Change PUK
                byte[] newPUK = Encoding.ASCII.GetBytes(newStr);

                var changeReferenceDataCommand = new ChangeReferenceDataCommand(PivSlot.Puk, oldPUK, newPUK);
                ChangeReferenceDataResponse changeReferenceDataResponse = connection.SendCommand(changeReferenceDataCommand);

                if (changeReferenceDataResponse.Status != ResponseStatus.Success)
                {
                    Console.WriteLine("Change PUK failed");
                }

                CryptographicOperations.ZeroMemory(oldPUK);
                CryptographicOperations.ZeroMemory(newPUK);
            }

            Console.WriteLine("Changed PUK successfully");
            return 0;
        }


        static IYubiKeyDevice ChooseYubiKey()
         {
             IEnumerable<IYubiKeyDevice> list = YubiKeyDevice.FindByTransport(Transport.UsbSmartCard);
             return list.First();
         }

        public static string RandomString(int length)
        {
            Random random = new();
            const string chars = "0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }




    }
}
