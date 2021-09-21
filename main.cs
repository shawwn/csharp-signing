using System;

class Program {
  public static void Main (string[] args) {
    foreach (var arg in args) {
      Console.WriteLine ("  {0}", arg);
    }
    string data = args[0];
    string privateKeyPath = args[1];
    string publicKeyPath = args[2];
    var signed = Crypto2.Sign(data, privateKeyPath, publicKeyPath);
    Console.WriteLine("{0}", signed);
  }
}