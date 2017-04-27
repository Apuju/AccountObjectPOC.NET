using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GoogleAuthenticator;
using System.IO;

namespace GoogleAuthenticatorSample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Do you want to create a new QR Code ? (Y/N)");
            string userInput = Console.ReadLine();
            string secretKey = string.Empty;
            if (userInput.ToUpper() == "Y")
            {
                QRCodeGenerator authenticator = new QRCodeGenerator("Aaron Su", "AaronSu@trend.com.tw");
                string imageURL = authenticator.GetQRCodeImageURL(320, 320);
                FileInfo fileinfo = new FileInfo(@"./QRCodeImage.txt");
                using (StreamWriter writer = new StreamWriter(fileinfo.Open(FileMode.OpenOrCreate, FileAccess.Write)))
                {
                    writer.Write(imageURL);
                }
                Console.WriteLine(imageURL);
                secretKey = authenticator.SecretKey;
                Console.WriteLine(secretKey);
            }
            if (string.IsNullOrEmpty(secretKey))
            {
                secretKey = "hxdmvjecjjwsrb3hwizr4ifugftmxboz";
            }
            OTPCodeHelper helper = new OTPCodeHelper();
            bool pass = false;
            string inputUserPINCode = string.Empty;
            while (!pass)
            {
                List<string> pinCodes = helper.GetCurrentPINCodes(secretKey, 1);
                foreach (string pinCode in pinCodes)
                {
                    Console.WriteLine(pinCode);
                }
                Console.WriteLine("Type your PIN code");
                inputUserPINCode = Console.ReadLine();
                pass = pinCodes.Any(p => p == inputUserPINCode);
                //pass = helper.VerifyGooglePINCode(secretKey, inputUserPINCode);
            }
            Console.WriteLine("END");
            Console.Read();
        }
    }
}
