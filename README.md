# SecureString Overview

An extension library for c# string objects providing one step encryption **and source memory buffer clearing** function for sensitive data.  Other libraries exists for encrypting a string but the critical way this one differs is **automatically** takes care to clear the source memory buffer which is missing in the native .NET SecureString and other libraries and is essential for reducing the attack surface for dumping or scanning memory for sensitive values.  This library extends both the String and built-in SecureString class in .NET which had very limited functionality and did not clear the source buffer.

# .NET Strings Are Immutable

Strings in .NET are constants, that is the value can not be changed even if the string is assigned a new value including String.Empty.  In each case the address is modified not the value, pointing to a new string or empty location leaving the original value disonnected but in memory until collected.  That presents a problem for keeping secrets safe in some scenarios.  Dumping memory is as easy as using Windows Task Manager and selecting the process and using the Dump Memory option for it then opening the file in Windows Debugger and scanning for what you want.  Further, oftentimes, debug symbols are left on the server for convenience or can be obtained and used to further simplify finding named variables like creditcard and values of interest.

# Security Starts with Reducing the Attack Surface 

Reducing the time in memory where values like cryptographic keys, government identification, credit card numbers, bank accounts or passwords are floating around waiting for garbage collection can reduce the attack window significantly and make it extremely difficult to hack.  In some cases the **.NET GC may take hours, days or longer to clear an object entirely from memory**.  Dumping memory is easy for anyone with system access for operations and maintanence and some processes running on the system which may scans memory for other processes and what their memory.  While control of access to systems running applications with sensitive data is key, defence in depth security principle requires we do more.

# ClearText Values Happen

Inputs coming over the internet once decrypted assuming TLS/SSL connection are no longer protected once delivered to the server after secure transit.  Sensitive data read from data sources likewise are often unprotected in process memory once received.  Often these values are needed for regular processing of data but are unprotected while not being used.  An ideal solution would enable nearly transparent converstion to an encrypted value and restoration when needed while ensureing the original string buffer that had the cleartext value is destroyed.

# SecureString Use

Developers should identify all sensitive values and store them as SecureString objects using this library and convert cleartext data received via forms input, file data read, API posted inputs or database reads from their unprotected String representation to SecureString objects using the **String.ToSecureString()** method which will automatically zero out the original string since clearly the intent is to protect the values.

If you need to recover the protected value in SecureString the ConvertToString provides a systematic way to do so that frees them having to locate and write code for it outside of the class type. They would likely want to clean up the now unprotected string created and may do so using the String.SecureClear() method provided.

# Quick Examples
```
String socialSecurity = Console.Readline();
SecureString ssNumber = socialSecurity;//automatically encryptes and clears socialSecurity source buffer
Console.WriteLine(ssNumber.ConvertToString());//decrypts
String creditCard = Console.ReadLine();
//processing
creditCard.SecureClear();
SecureString ssNumber2 = ssnumber.ConvertToString().ToSecureString();
bool isEqual = ssNumber.SecureCompare(ssNumber2);
String hashValue = ssNumber.SHA256HashValue();
```
