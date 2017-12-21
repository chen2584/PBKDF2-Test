using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace consoleTest
{
    class Program
    {
        static void Main(string[] args)
        {
            /*string[] passwords = {  
                "PASSWORD",  
                "P@SSW0RD",  
                "password",  
                "p@ssw0rd"  
            };  
            foreach(var password in passwords)  
            {  
                string salt = getSalt();  
                Console.WriteLine($@"{{'password': '{password}', 'salt': '{salt}', 'hash': '{getHash(password + salt)}'}}");  
         
            }  */

            // Arrange
            var message = "passw0rd";
            var salt = Salt.Create();
            var hash = Hash.Create(message, salt);
 
            // Act
            //var match = Hash.Validate(message, salt, hash);
 
            // Assert
            Console.WriteLine(hash);

        }

        

        static string getHash(string text)  
        {  
            // SHA512 is disposable by inheritance.  
            using(var sha256 = SHA256.Create())  
            {  
                // Send a sample text to hash.  
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(text));  
                // Get the hashed string.  
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();  
            }  
        }  

        private static string getSalt()  
        {  
            byte[] bytes = new byte[128 / 8];  
            using(var keyGenerator = RandomNumberGenerator.Create())  
            {  
                keyGenerator.GetBytes(bytes);  
                return BitConverter.ToString(bytes).Replace("-", "").ToLower();  
            }  
        }  

        
    }

    public class Hash
    {
        public static string Create(string value, string salt)
        {
            var valueBytes = KeyDerivation.Pbkdf2(
                                password: value,
                                salt: Encoding.UTF8.GetBytes(salt),
                                prf: KeyDerivationPrf.HMACSHA512,
                                iterationCount: 10000,
                                numBytesRequested: 256 / 8);
 
            return Convert.ToBase64String(valueBytes);
        }
 
        public static bool Validate(string value, string salt, string hash)
            => Create(value, salt) == hash;
    }

    public class Salt
    {
        public static string Create()
        {
            byte[] randomBytes = new byte[128 / 8];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(randomBytes);
                return Convert.ToBase64String(randomBytes);
            }
        }
    }

}
