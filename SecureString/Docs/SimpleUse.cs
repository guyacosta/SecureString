////////////////////////////////////////////////////////////////////////////////////////////////////
/* Copyright: Microsoft (c) 2018
 * Author: Guy Acosta, Sr. Security Engineer, Microsoft Digital Security Risk Engineering, ACE Team
 * Description: Extension class methods for securing use of String objects in conversion to and
 * from SecureString class objects and protecting memory contents of sensitive data
 * Date created: 7/19/2018
 * Use: Intended for use within Microsoft after additional evaluation
 * 
 * */
////////////////////////////////////////////////////////////////////////////////////////////////////


using System;
using System.Security;
using SecureStringPlus;


namespace SecureStringPOC
{
    /// <summary>
    /// VERY quick and dirty illustration of SecureString and String extensions library to generalize a solution.
    /// New SecureString and String extension methods are demonstrated for securing sensitive values in memory by
    /// reducing the time spent in unprotected clear text form in favor of encryption and when needed decryption
    /// methods that are added.  Uses SecureStringExt class library for new methods.  Largely meant to be run
    /// as a whitebox test with output.
    /// 
    /// POC uses unsafe/fixed keywords to allocate char pointers to strings for illustrating memory contents before
    /// and after use of new extension methods.  Use of the library would not require direct use of these and would
    /// hide implementation details away from developer but does require the project to have the "allow unsafe" property
    /// to be enabled.  
    /// 
    /// Methods demonstrated include:
    /// String.ToSecureString(); e.g. String myData = Console.Readline(); SecureString secret = myData.ToSecureString();
    /// String.SecureClear(); e.g. myData.SecureClear(); 
    /// SecureString.ConvertoToString(); e.g. String recoverData = secret.ConvertToString();
    /// SecureString.SecureCompare(SecureString arg2); e.g. SecureString anotherSecret = myData.ToSecureString(); bool test = secret.SecureCompare(anotherSecret);
    /// SecureString.SHA256HashValue();String hash = secret.SHA256HashValue();
    /// 
    /// See POCReadme.txt for more notes on expected usage and getter/setter aspects
    /// 
    /// </summary>
    class Proof
    {
        static void Main(string[] args)
        {

            Console.WindowWidth = Console.LargestWindowWidth / 2 + 40;
            Console.WindowHeight = Console.LargestWindowHeight / 2;

            Console.WriteLine("*****************Secure String Extension Quick Demo**************************");
            
            //Request input to show delta with string literals later...
            Console.Write("Enter password, secret or auth token: ");
            String clearText1 = Console.ReadLine();

            SecureString ssNumber = clearText1.ToSecureString();
            Console.WriteLine(ssNumber.ToString());//junk
            String clearText4 = ssNumber.ConvertToString();
            Console.WriteLine(clearText4);

            int length = ssNumber.Length;//get the length without exposing cleartext value
            int hash = ssNumber.GetHashCode();
            //ssNumber.InsertAt(0, 'T');won't work unless specify as mutable on create i.e. ToSecureString(false);
            //ssNumber.AppendChar('V');
            clearText4 = ssNumber.ConvertToString();
            SecureString copy = ssNumber.Copy();
            String clearText5 = copy.ConvertToString();

        }

    }

}
