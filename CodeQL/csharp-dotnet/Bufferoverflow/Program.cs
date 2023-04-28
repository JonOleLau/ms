using System;
using System.Text;

namespace BufferOverflowExample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter your name:");
            string name = Console.ReadLine();

            // Here's the magic! We'll create a tiny buffer and force it to overflow.
            byte[] smallBuffer = new byte[2];
            Buffer.BlockCopy(Encoding.ASCII.GetBytes(name), 0, smallBuffer, 0, name.Length);

            Console.WriteLine("Hello, {0}!", Encoding.ASCII.GetString(smallBuffer));
        }
    }
}
