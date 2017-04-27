using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace GoogleAuthenticator
{
    public class OTPCodeHelper
    {
        private readonly DateTime UNIX_EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private readonly int digits = 6;
        private readonly int timeStep = 30;
        
        public List<string> GetCurrentPINCodes(string secret, int clockDriftToleranceByMinutes)
        {
            List<string> pinCodes = new List<string>();
            
            
            long iterationCounter = (long)(DateTime.UtcNow - UNIX_EPOCH).TotalSeconds / timeStep;

            int iterationOffset = 0;
            TimeSpan timeDriftTolerance = TimeSpan.FromMinutes(clockDriftToleranceByMinutes);
            iterationOffset = Convert.ToInt32(timeDriftTolerance.TotalSeconds / Convert.ToDouble(timeStep));
            
            long iterationStart = iterationCounter - iterationOffset;
            long iterationEnd = iterationCounter + iterationOffset;
            for (long counter = iterationStart; counter <= iterationEnd; counter++)
            {
                pinCodes.Add(GenerateHashedCode(secret, counter));
            }

            return pinCodes;
        }

        public string GenerateHashedCode(string secret, long iterationNumber)
        {
            byte[] key = Encoding.UTF8.GetBytes(secret);

            byte[] counter = BitConverter.GetBytes(iterationNumber);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(counter);

            HMACSHA1 hmac = new HMACSHA1(key, true);

            byte[] hash = hmac.ComputeHash(counter);

            int offset = hash[hash.Length - 1] & 0xf;

            int binary =
                ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

            int password = binary % (int)Math.Pow(10, digits); // 6 digits

            return password.ToString(new string('0', digits));
        }

        public bool VerifyGooglePINCode(string secret, string inputPINCode)
        {
            bool validation = false;
            List<string> pinCodes = GetCurrentPINCodes(secret, 1);
            validation = pinCodes.Any(pinCode => pinCode == inputPINCode);
            return validation;
        }
    }
}
