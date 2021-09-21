using System;
using System.IO;

// dotnet add main.csproj package System.CommandLine --prerelease
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Invocation;

class Program {
  static int Main(string[] args) {
    var signCommand = new Command ("sign") {
      new Option<string>(
          new []{"-d", "--data"},
          "The data to sign. If you start the data with the letter @, the rest should be a filename.")
    };
    signCommand.Description = "Sign some data";

    var rootCommand = new RootCommand {
      new Option<FileInfo>(
          new []{"-k", "--key", "--private-key"},
          getDefaultValue: () => new FileInfo("sign.key"),
          description: "The private .key file used for signing")
        .ExistingOnly(),
        new Option<FileInfo>(
            new []{"-p", "--crt", "--public-key"},
            getDefaultValue: () => new FileInfo("sign.crt"),
            description: "The public .crt file used for signing")
          .ExistingOnly(),
        signCommand,
    };
    rootCommand.Description = "For signing data";

    // Note that the parameters of the handler method are matched according to the names of the options
    signCommand.Handler = CommandHandler.Create<FileInfo, FileInfo, string>((privateKey, publicKey, data) =>
        SignCommand(privateKey?.FullName, publicKey?.FullName, data));

    // Parse the incoming args and invoke the handler
    return rootCommand.InvokeAsync(args).Result;
  }
  public static void SignCommand (string key, string crt, string data) {
    if (data.Length > 0 && data.StartsWith("@")) {
      var bytes = File.ReadAllBytes(data.Substring(1));
      var signed = Crypto2.Sign(bytes, key, crt);
      Console.WriteLine("{0}", signed);
    } else {
      var signed = Crypto2.Sign(data, key, crt);
      Console.WriteLine("{0}", signed);
    }
  }
}