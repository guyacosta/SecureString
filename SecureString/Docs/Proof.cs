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

            #region read INPUT 

            Console.WindowWidth = Console.LargestWindowWidth / 2 + 40;
            Console.WindowHeight = Console.LargestWindowHeight / 2;

            Console.WriteLine("*****************Secure String Extension Quick Demo**************************");
            Console.WriteLine("Use the console output, Visual Studio or another debugger to verify memory impact directly.\n");

            //Request input to show delta with string literals later...
            Console.Write("Enter userid: ");
            String sensitiveData1 = Console.ReadLine();
            Console.Write("Enter password, secret or auth token: ");
            String sensitiveData2 = Console.ReadLine();
            Console.Write("Enter social security number: ");
            String sensitiveData3 = Console.ReadLine();
            Console.WriteLine("");

            #endregion

            //defined prior to fixed keyword scopes for used later after scope block end
            SecureString secure1, secure2, secure3;
            String peek;

            /////SHOW STRING IS IMMUTABLE MAKING IT HARD TO CLEAR SENSITIVE VALUES OUT

            Console.WriteLine("Task 1 of 4: illustrate string is immutable normally and can not be cleared...");
            Console.WriteLine("");

            unsafe //tell compiler we will manage memory in this block to allow us to peek into String buffers to verify contents
            {
                //tell GC not to move or free the pointer p in this block with fixed keyword so we can peek at memory safely
                fixed (char* ptr1 = sensitiveData1) //pointer userid memory buffer
                {
                    //Failed attempts to clear actually create a new empty string at a new location while value at old memory value at ptr1 is unchanged
                    sensitiveData1 = "";
                    sensitiveData1 = String.Empty;

                    //Verify unchanged but disconnected memory buffer value using new String peek from char*
                    peek = new String(ptr1);
                    Console.WriteLine("Userid is readable at memory location " + ((int)ptr1).ToString("X") + " after attempt to empty without extension: " + peek);
                    //To clear ptr1 buffer we have to do manually within fixed block...compare to extended methods below since can't reassign ptr1 buffer location to sensitiveData1 again
                    for (int i = 0; i < peek.Length; i++) ptr1[i] = '\0';

                    //Restore original input [value] to sensitiveData1; both point to same peek location not to original ptr1 address
                    sensitiveData1 = peek;

                    /////SHOW SECURESTRING LEAVES ORIGINAL STRING IN CLEARTEXT TO COMPARE WITH NEW METHODS BELOW

                    fixed (char* ptr2 = sensitiveData2)//create pointer to password memory buffer
                    {
                        SecureString partialHelp = new SecureString(ptr2, sensitiveData2.Length);
                        //partialHelp is encrypted but original String memory buffer at ptr2 and sensitiveData2 remain in clear text
                        Console.WriteLine("Password value remains unprotected in String and is readable at memory location " + ((int)ptr2).ToString("X") + " after creating SecureString WITHOUT new extension methods: " + sensitiveData2);

                        Console.WriteLine("press [enter] key");
                        Console.ReadKey();
                        Console.WriteLine("");

                        fixed (char* ptr3 = sensitiveData3)//create pointer to social 
                        {
                            /////NOW VERIFY THE NEW EXTENSION WORKS
                            Console.WriteLine("Task 2 of 4: Show new SecureString extensions clean up original memory values...");
                            Console.WriteLine("");

                            //NEW extension: Converts String to Securestring AND zeros out the original cleartext string in one step!
                            secure1 = sensitiveData1.ToSecureString();
                            //Verify pointer ptr2 in memory window is zeroed or use peek string show the memory is cleared = success!
                            peek = new String(ptr1);//peek back original memory buffer for changed value
                            Console.WriteLine("Userid string buffer at memory location " + ((int)ptr1).ToString("X") + " after new String.ToSecureString() call is automatically emptied : " + peek);

                            //NEW extension: Converts String to Securestring AND zeros out the original cleartext string in one step!
                            secure2 = sensitiveData2.ToSecureString();
                            //Verify pointer ptr2 in memory window is zeroed or use peek string show the memory is cleared = success!
                            peek = new String(ptr2);//peek back original memory buffer for changed value
                            Console.WriteLine("Original Password string buffer at memory location " + ((int)ptr2).ToString("X") + " after new String.ToSecureString() call is automatically emptied : " + peek);

                            //Repeat: NEW extension: Converts string to secure string and zeros out the original cleartext string in one step!
                            secure3 = sensitiveData3.ToSecureString();
                            peek = new string(ptr3);//peek back original memory buffer for changed value
                            Console.WriteLine("Original Social security string buffer at memory location " + ((int)ptr3).ToString("X") + " after new String.ToSecureString() call is automatically emptied : " + peek);
                        }
                    }
                }
            }


            Console.WriteLine("press [enter] key");
            Console.ReadKey();
            Console.WriteLine("");

            //////OTHER USEFUL ADD ON EXTENSION METHODS

            Console.WriteLine("Task 3 of 4: demo other key extension methods...");
            Console.WriteLine("");
            //Use addon SAFE COMPARISON of the cipher text value safely without exposure
            bool isEqual = secure2.SecureCompare(secure3);
            String resultAdd = isEqual ? "are EQUAL" : "are NOT equal";
            Console.WriteLine("New SecureString.SecureCompare() method safely detects value equality e.g. password and social security inputs " + resultAdd);

            //Use DECRYPT extension method for convenient way to retrieve value for use with API's that require String objects
            String getvalueBack = secure3.ConvertToString();
            Console.WriteLine("New SecureString.ConvertToString() decryption method can recover values e.g. Social Security Number : " + getvalueBack);

            //Use SECURECLEAR extended method convenvience to take existing [String] and just zero out.  
            getvalueBack.SecureClear();
            Console.WriteLine("Recovered unprotected Strings (e.g. SSNo.) can be securely cleared using String.SecureClear() extended method: " + getvalueBack);

            //SECURECLEAR ONCE -securely clear a value many function levels down and see how the original and all stack references are cleared value too
            sensitiveData2 = secure2.ConvertToString();
            function1(sensitiveData2);
            Console.WriteLine("Sensitive strings may be securely cleared from lower level nested function calls e.g.: " + sensitiveData2);

            Console.WriteLine("press [enter] key");
            Console.ReadKey();
            Console.WriteLine("");

            Console.WriteLine("Task 4 of 4: demo additional extension methods and safeguard...");
            Console.WriteLine("");
            //get a SHA256 hash of the secure value
            String hashValue = secure2.SHA256HashValue();
            Console.WriteLine("New SecureString.SHA256HashValue() support is included e.g. password hash is : " + hashValue);

            //Illustrates how STRING LITERALS / INTERNED STRINGS are protected from accidental zeroing as program logic
            //expects a constant value to be there etc.; Note: if a dynamic input matches the literal value it too will not be zero'd
            //out but as no sensitive data should be a program literal to be SDL compliant this should never actually happen 
            String myLiteral = "DoNotDeleteAsCodeIsDependentOnThis";
            try
            {
                myLiteral.SecureClear();//shows it is protected from accidential deletion
            }
            catch (Exception e)
            {
                Console.WriteLine("String literal safeguards block attempts to clear .NET interned values e.g. String myLiteral = \"DoNotDeleteAsCodeIsDependentOnThis\";\nmyLiteral.SecureClear(); results in: " + e.Message);
            }


            //Use built in SecureString dispose to safely dispose of [cipher] text with Using pattern or let it
            //just go out of scope...it will also safely clear the encrypted object
            secure2.Dispose();
            secure3.Dispose();

            Console.WriteLine("");
            Console.WriteLine("   Hey, what's in your client or server app memory?");
            Console.WriteLine("");
            Console.WriteLine("***************End: Secure String Quick Demo************************");
            Console.WriteLine("\npress [enter] to end");
            Console.ReadKey();
        }




        static void function1(string one)
        {
            function2(one);
        }

        static void function2(string two)
        {
            function3(two);
        }

        static void function3(string three)
        {
            //all string references are pointing to same memory buffer unless one of them is changed via
            //reassignment so we can when done with a value, clear them all from down here
            three.SecureClear();
        }

    }

   

}
