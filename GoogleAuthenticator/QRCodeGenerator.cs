using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using EncryptDecryptHelper;

namespace GoogleAuthenticator
{
    public class QRCodeGenerator
    {
        private string m_IssueUser = string.Empty;
        private string m_IssueUserMailAddress = string.Empty;
        private string m_Algorithm = "SHA1";
        private int m_Period = 30;
        private string m_Secrect = string.Empty;

        public string SecretKey
        {
            get
            {
                return m_Secrect;
            }
        }

        public QRCodeGenerator(string issueUser, string issuerUserMailAdress)
        {
            m_IssueUser = issueUser;
            m_IssueUserMailAddress = issuerUserMailAdress;
        }

        public string GetQRCodeImageURL(int width, int height)
        {
            //A cryptographic Random Number Generator
            //https://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider%28v=vs.110%29.aspx
            string secrectString = "hxdmvjecjjwsrb3hwizr4ifugftmxboz";
            //string randomString = "hxdm vjec jjws rb3h wizr 4ifu gftm xboz";
            string provisionURL = string.Empty;
            using(RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                //byte[] randomBytes = new byte[10];
                //rng.GetBytes(randomBytes);
                //Regex reg = new Regex(@"/[\s\.-_]+/g", RegexOptions.IgnoreCase);
                //m_RandomString = reg.Replace(randomString, string.Empty).ToUpper();
                m_Secrect = secrectString;
                EncryptHelper encryptHelper = new EncryptHelper();
                // Full OTPAUTH URI spec as explained at
                // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
                provisionURL = HttpUtility.UrlEncode(String.Format("otpauth://totp/{0}:{1}?secret={2}&issuer={3}&algorithm={4}&digits=6&period={5}", m_IssueUser, m_IssueUserMailAddress, encryptHelper.EncodeBase32(m_Secrect), m_IssueUser, m_Algorithm, m_Period.ToString()));
            }
            return String.Format("http://chart.apis.google.com/chart?cht=qr&chs={0}x{1}&chl={2}", width.ToString(), height.ToString(), provisionURL);
        }
    }
}
