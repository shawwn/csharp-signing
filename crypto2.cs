using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;

public class Crypto2
{
  private static RsaKeyParameters MakeKey(String modulusHexString, String exponentHexString, bool isPrivateKey)
  {
    var modulus = new BigInteger(modulusHexString);
    var exponent = new BigInteger(exponentHexString);
    return new RsaKeyParameters(isPrivateKey, modulus, exponent);
  }
  public static string SignMod(string data, string privateModulusHexString, string privateExponentHexString)
  {
    /* Make the key */
    RsaKeyParameters key = MakeKey(privateModulusHexString, privateExponentHexString, true);
    /* Init alg */
    ISigner sig = SignerUtilities.GetSigner("SHA256WITHRSA");
    /* Populate key */
    sig.Init(true, key);
    /* Get the bytes to be signed from the string */
    var bytes = Encoding.UTF8.GetBytes(data);
    /* Calc the signature */
    sig.BlockUpdate(bytes, 0, bytes.Length);
    byte[] signature = sig.GenerateSignature();
    /* Base 64 encode the sig so its 8-bit clean */
    var signedString = Convert.ToBase64String(signature);
    return signedString;
  }
  public static bool Verify(string data, string expectedSignature, string publicModulusHexString, string publicExponentHexString)
  {
    /* Make the key */
    RsaKeyParameters key = MakeKey(publicModulusHexString, publicExponentHexString, false);
    /* Init alg */
    ISigner signer = SignerUtilities.GetSigner("SHA256WITHRSA");
    /* Populate key */
    signer.Init(false, key);
    /* Get the signature into bytes */
    var expectedSig = Convert.FromBase64String(expectedSignature);
    /* Get the bytes to be signed from the string */
    var msgBytes = Encoding.UTF8.GetBytes(data);
    /* Calculate the signature and see if it matches */
    signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
    return signer.VerifySignature(expectedSig);
  }
  public static string Sign(string data, string privateKeyPath, string publicKeyPath)
  {
    var key = ReadPrivateKey(privateKeyPath);
    var publicKey = ReadCertificate(publicKeyPath);
    var signedData = Crypto2.SignMod(data, key.Modulus.ToString(), key.Exponent.ToString());
    bool result = Crypto2.Verify(data, signedData, ((RsaKeyParameters)publicKey.GetPublicKey()).Modulus.ToString(), ((RsaKeyParameters)publicKey.GetPublicKey()).Exponent.ToString());
    if (!result) {
      throw new Exception("Unable to verify");
    }
    return signedData;
  }
  static RsaKeyParameters ReadPrivateKey(string privateKeyFileName)
  {
    using (var reader = File.OpenText(privateKeyFileName)) {
      var obj = new PemReader(reader).ReadObject();
      var keyPair = (RsaKeyParameters)obj;
      return keyPair;
    }
  }
  static X509Certificate ReadCertificate(string filename)
  {
    X509CertificateParser certParser = new X509CertificateParser();
    Stream stream = new FileStream(filename, FileMode.Open);
    X509Certificate cert = certParser.ReadCertificate(stream);
    stream.Close();
    return cert;
  }
}