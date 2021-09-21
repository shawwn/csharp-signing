using System;
using System.IO;
using System.Text;

// dotnet add main.csproj package System.CommandLine --prerelease
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Invocation;

class Program {
  static int Main(string[] args) {
    var signCommand = new Command ("sign") {
      new Option<FileInfo>(
          new []{"-k", "--key", "--private-key"},
          getDefaultValue: () => new FileInfo("sign.key"),
          description: "The private .key file used for signing")
      .ExistingOnly(),
      new Option<string>(
          new []{"-d", "--data"},
          "The data to sign. If you start the data with the letter @, the rest should be a filename.")
    };
    signCommand.Description = "Sign data";

    var verifyCommand = new Command ("verify") {
      new Option<FileInfo>(
          new []{"-p", "--crt", "--public-key"},
          getDefaultValue: () => new FileInfo("sign.crt"),
          description: "The public .crt file used for verification")
      .ExistingOnly(),
      new Option<string>(
          new []{"-s", "--sig", "--signature"},
          "The digital signature (base64)."),
      new Option<string>(
          new []{"-d", "--data"},
          "The data to verify. If you start the data with the letter @, the rest should be a filename.")
    };
    verifyCommand.Description = "Verify signed data";

    var rootCommand = new RootCommand {
      signCommand,
      verifyCommand,
    };
    rootCommand.Description = "For signing or verifying data";

    // Note that the parameters of the handler method are matched according to the names of the options
    signCommand.Handler = CommandHandler.Create<FileInfo, string>((privateKey, data) =>
        SignCommand(privateKey?.FullName, data));
    verifyCommand.Handler = CommandHandler.Create<FileInfo, string, string>((publicKey, signature, data) =>
        VerifyCommand(publicKey?.FullName, signature, data));

    // Parse the incoming args and invoke the handler
    return rootCommand.InvokeAsync(args).Result;
  }
  public static byte[] GetBytes(string data) {
    if (data.Length > 0 && data.StartsWith("@")) {
      var bytes = File.ReadAllBytes(data.Substring(1));
      return bytes;
    } else {
      return Encoding.UTF8.GetBytes(data);
    }
  }
  public static void SignCommand (string key, string data) {
    var bytes = GetBytes(data);
    var signed = Crypto2.Sign(bytes, key);
    Console.WriteLine("{0}", signed);
  }
  public static void VerifyCommand (string key, string sig, string data) {
    var bytes = GetBytes(data);
    var verified = Crypto2.Verify(bytes, sig, key);
    //Console.WriteLine($"key={key}, sig={sig}, data={data}");
    Console.WriteLine("{0}", verified);
  }
}