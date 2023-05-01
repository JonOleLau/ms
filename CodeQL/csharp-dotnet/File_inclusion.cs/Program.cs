using System;
using System.IO;

namespace FileInclusion
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter a filename: ");
            string userInput = Console.ReadLine();

            if (string.IsNullOrEmpty(userInput))
            {
                Console.WriteLine("Please specify a file to read.");
                return;
            }

            // Vulnerable code: concatenate userInput to the filepath without validating it
            string filepath = Path.Combine(Environment.CurrentDirectory, userInput);

            // Check if the file exists
            if (!File.Exists(filepath))
            {
                Console.WriteLine("The specified file does not exist.");
                return;
            }

            // Read the contents of the file
            string fileContents = File.ReadAllText(filepath);

            Console.WriteLine(fileContents);
        }
    }
}
