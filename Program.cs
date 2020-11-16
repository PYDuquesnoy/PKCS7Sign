using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
///Library reference System.Security
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
/*
 * Create Self Signed Cert for testing
 * From ubuntu shell:
 *   openssl genrsa 2048 > private.key
 *   openssl req -new -x509 -nodes -sha1 -days 1000 -key private.key > public.cer
 *   openssl pkcs12 -export -in public.cer -inkey private.key -out cert_key.p12
 */

/*
 * ** openssl smime -sign -nocerts -in file -out file.sgn -inkey private.key -signer public.cer -md sha1
 * openssl smime -sign  -in file -out file.sgn -inkey private.key -signer public.cer -md sha1
 * openssl smime -verify -in file.sgn -noverify -certfile public.cer
 * openssl cms -in file.sgn -noout -cmsout -print
 * 
 */
namespace PKCS7console
{
class Program
{
    //PKCS7console via dat certfile outfile
    static void Main(string[] args)
    {
        //Console.WriteLine("Starting...");
        if (args.Length!=3)
        {
            Console.WriteLine("3 Arguments needed: VIA=xxx&DAT=yyy certFilenameP12 outFilename ");
            return;
        }
        
        ///String Cadena = "VIA=" + VIA + "&DAT=" + DAT;
        String cadena = args[0];
        String certFilename = args[1];
        String outFilename = args[2];

            
            //Console.WriteLine("cadena a firmar:" + cadena);
           
        ///Now Try to sign
        byte[] msgBytes = Encoding.UTF8.GetBytes(cadena);
        ContentInfo content = new ContentInfo(msgBytes);

        //SignedCms signedCms = new SignedCms(SubjectIdentifierType.IssuerAndSerialNumber, contentInfo, chkDetached.Checked);
        SignedCms signedMessage = new SignedCms(content,true); ///PYD: Detached

        //---
        CmsSigner cmsSigner = new CmsSigner();
        //String pCertFile = "c:\\cert\\cert_key.p12";
        String pPassword = "";
        X509Certificate2 signingCertificate= new X509Certificate2(certFilename,pPassword, System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.DefaultKeySet);

        //X509Certificate2 signingCertificate = this.GetCertificate();
        cmsSigner.Certificate = signingCertificate;
        //cmsSigner.IncludeOption = X509IncludeOption.ExcludeRoot;

        // SHA1 OID = 1.3.14.3.2.26, SHA256 OID = 2.16.840.1.101.3.4.2.1
        cmsSigner.DigestAlgorithm = new Oid("1.3.14.3.2.26");
        //new Pkcs9ContentType()
        cmsSigner.SignedAttributes.Add(new Pkcs9SigningTime());
        
        /*
        //S/Mime Capabilities: Attribute(3): PKCS#9 S/MIME Capabilities: <cap. Info>
        //S/MiME:"1.2.840.113549.1.9.15"
        byte[] smimeContent =new byte [1];
        smimeContent[0] = 0;
        Pkcs9AttributeObject smimeCapabilities = new Pkcs9AttributeObject("1.2.840.113549.1.9.15",smimeContent);
        cmsSigner.SignedAttributes.Add(smimeCapabilities);
        */

        signedMessage.ComputeSignature(cmsSigner, false);  //silent:false
        byte[] myCmsMessage = signedMessage.Encode();
        //Console.WriteLine("Base64Encoded:");
        //Console.WriteLine(Convert.ToBase64String(myCmsMessage));
        
        using (System.IO.StreamWriter file = 
            new System.IO.StreamWriter(@outFilename))
            {
                file.WriteLine(Convert.ToBase64String(myCmsMessage));
            }
        //---myCmsMessage ready to be sent.
        // BitConverter can also be used to put all bytes into one string  
        /*
        string bitString = BitConverter.ToString(myCmsMessage);
        Console.WriteLine(bitString);
        Console.WriteLine("");
        */

        /*
        // UTF conversion - String from bytes  
        string utfString = Encoding.UTF8.GetString(myCmsMessage, 0, myCmsMessage.Length);
        Console.WriteLine(utfString);
        Console.WriteLine(signedMessage.ToString());
        */
    }
}
}
