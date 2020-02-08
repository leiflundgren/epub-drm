using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace inept_net
{
    public class KeyHandling
    {
        public static class win32_import
        {
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            [System.Diagnostics.DebuggerDisplay("len={cbData}, ptr={pbData}")]
            private struct DATA_BLOB
            {
                public int cbData;
                public IntPtr pbData;

                public static DATA_BLOB Create(byte[]data)
                {
                    DATA_BLOB blob = new DATA_BLOB();
                    blob.cbData = Marshal.SizeOf(data[0]) * data.Length;
                    blob.pbData = Marshal.AllocHGlobal(blob.cbData);

                    Marshal.Copy(data, 0, blob.pbData, data.Length);

                    return blob;
                }

                public static void Dealloc(DATA_BLOB blob)
                {
                    if ( blob.pbData != IntPtr.Zero )
                        Marshal.FreeHGlobal(blob.pbData);
                }
            }


            [Flags]
            private enum CryptProtectFlags {

                NONE = 0x0,

                // for remote-access situations where ui is not an option
                // if UI was specified on protect or unprotect operation, the call
                // will fail and GetLastError() will indicate ERROR_PASSWORD_RESTRICTION
                CRYPTPROTECT_UI_FORBIDDEN = 0x1,

                // per machine protected data -- any user on machine where CryptProtectData
                // took place may CryptUnprotectData
                CRYPTPROTECT_LOCAL_MACHINE = 0x4,

                // force credential synchronize during CryptProtectData()
                // Synchronize is only operation that occurs during this operation
                CRYPTPROTECT_CRED_SYNC = 0x8,

                // Generate an Audit on protect and unprotect operations
                CRYPTPROTECT_AUDIT = 0x10,

                // Protect data with a non-recoverable key
                CRYPTPROTECT_NO_RECOVERY = 0x20,


                // Verify the protection of a protected blob
                CRYPTPROTECT_VERIFY_PROTECTION = 0x40
            }
            [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptUnprotectData(
                ref DATA_BLOB pDataIn,
                StringBuilder szDataDescr,
                ref DATA_BLOB pOptionalEntropy,
                IntPtr pvReserved,
                IntPtr /*ref CRYPTPROTECT_PROMPTSTRUCT*/ pPromptStruct,
                CryptProtectFlags dwFlags,
                ref DATA_BLOB pDataOut
            );

            public static byte[] CryptUnprotectData(byte[] indata, byte[] entropy)
            {
                DATA_BLOB blob_in = default(DATA_BLOB), blob_entropy = default(DATA_BLOB), blob_out = default(DATA_BLOB);


                try
                {
                    blob_in = DATA_BLOB.Create(indata);
                    blob_entropy = DATA_BLOB.Create(entropy);

                    bool rc = CryptUnprotectData(ref blob_in, null, ref blob_entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectFlags.NONE, ref blob_out);
                    if ( !rc )
                    {
                        int err = Marshal.GetLastWin32Error();
                        string errorMessage = new System.ComponentModel.Win32Exception(err).Message;
                        throw new Exception("CryptUnprotectData failed " + err + ": " + errorMessage);
                    }

                    byte[] res = new byte[blob_out.cbData];
                    Marshal.Copy(blob_out.pbData, res, 0, blob_out.cbData);
                    return res;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Failed to uncrypt keykey. Using hardcoded from python.");
                    Console.Error.WriteLine(ex.Message);

                    return new byte[] { 0x6c, 0x1c, 0xdd, 0xfe, 0x0f, 0x90, 0x30, 0x96, 0x1d, 0x98, 0xb9, 0x63, 0x99, 0x94, 0xaf, 0xf9 };
                }
                finally
                {
                    DATA_BLOB.Dealloc(blob_in);
                    DATA_BLOB.Dealloc(blob_entropy);
                    DATA_BLOB.Dealloc(blob_out);
                }


            }
        }


        public static string GetRootDrive()
        {
            string sysdir = Path.GetPathRoot(Environment.SystemDirectory);            
            return sysdir.Substring(0, sysdir.IndexOf(':'));
        }

        public static string GetVolumeSerialNumber(string driveName)
        {
            System.Management.ManagementObject disk = new System.Management.ManagementObject("win32_logicaldisk.deviceid=\"" + driveName + ":\"");
            disk.Get();
            string SerialNumber = disk["VolumeSerialNumber"].ToString();
            return SerialNumber;
        }

        public class EntropySource
        {
            private byte[] vendor;
            private byte[] signature;
            public byte[] Entropy { get; private set; }

            public EntropySource()
            {
                RootVolumeSerial = GetVolumeSerialNumber(GetRootDrive());
                RootVolumeSerialNumber = UInt32.Parse( RootVolumeSerial, System.Globalization.NumberStyles.HexNumber );
                byte[] serial_big_endian = BitConverter.GetBytes( swapEndianness(RootVolumeSerialNumber) );

                vendor = CpuID_b.CPUID0();
                if ( vendor.Length != 12 )
                {
                    byte[] old = vendor;
                    vendor = new byte[12];
                    Array.Clear(vendor, 0, vendor.Length);
                    Array.Copy(old, 0, vendor, 0, Math.Min(12, vendor.Length));
                }

                byte[] cpuid1 = CpuID_b.CPUID1();
                UInt32 ui = BitConverter.ToUInt32(cpuid1, 0);
                byte[] s_0 = BitConverter.GetBytes( swapEndianness(ui) );
                
                signature = new byte[] { s_0[1], s_0[2], s_0[3]}; // byte 1-3, skip pos 0

                Username = Environment.UserName;

                byte[] username_array = new byte[32];
                Array.Clear(username_array, 0, username_array.Length);
                byte[] username_ascii = Encoding.ASCII.GetBytes(Username);
                Array.Copy(username_ascii, username_array, username_ascii.Length);

                int pos=0;
                Entropy = new byte[32];
                
                Array.Copy( serial_big_endian, 0, Entropy, pos, 4);
                pos += 4;

                Array.Copy( vendor, 0, Entropy, pos, 12);
                pos += 12;

                Array.Copy( username_array, 0, Entropy, pos, 13);
                pos += 13;
            }

            private static UInt32 swapEndianness(UInt32 x)
            {
                return ((x & 0x000000ff) << 24) +  // First byte
                       ((x & 0x0000ff00) << 8) +   // Second byte
                       ((x & 0x00ff0000) >> 8) +   // Third byte
                       ((x & 0xff000000) >> 24);   // Fourth byte
            }

            public string RootVolumeSerial;
            public UInt32 RootVolumeSerialNumber;
            public string Vendor
            {
                get
                {
                    if (vendor == null)
                        return string.Empty;
                    else
                        return Encoding.ASCII.GetString(vendor);
                }
            }
            public byte[] VendorBytes { get { return vendor; } set { vendor = value; } }

            //public string Signature
            public string Username;
        }

        public static EntropySource GetEntropySource()
        {
            return new EntropySource {
                RootVolumeSerial = GetVolumeSerialNumber(GetRootDrive()),

            };
        }


        const string DEVICE_KEY_PATH = @"Software\Adobe\Adept\Device";
        const string PRIVATE_LICENCE_KEY_PATH = @"Software\Adobe\Adept\Activation";

        public static byte[] GetDeviceKey()
        {
            using ( RegistryKey k = Registry.CurrentUser.OpenSubKey(DEVICE_KEY_PATH) )
            {
                if ( k == null ) throw new ArgumentException("Adobe Digital Editions not activated");

                return (byte[]) k.GetValue("key");
            }
        }

        public static byte[] GetPrivateLicenceKey()
        {
            string b64 = GetPrivateLicenceKeyBase64();
            if (b64 == null)
                return null;
            else
                return Convert.FromBase64String(b64);
        }


        public static string GetPrivateLicenceKeyBase64()
        {
            using ( RegistryKey root = Registry.CurrentUser.OpenSubKey(PRIVATE_LICENCE_KEY_PATH) )
            {
                if ( root == null ) throw new ArgumentException("Could not locate ADE activation");

                return GetPrivateLicenceKeyBase64(root);
            }
        }
        

        public static string GetPrivateLicenceKeyBase64(RegistryKey key)
        {
            if ( (string)key.GetValue("") == "privateLicenseKey")
            {
                return (string) key.GetValue("value");
            }

            foreach ( string subkeyName in key.GetSubKeyNames())
            {
                using ( RegistryKey subkey = key.OpenSubKey(subkeyName) )
                {
                    string res = GetPrivateLicenceKeyBase64(subkey);
                    if ( res != null )
                        return res;
                }
            }

            return null;
        }

        #region Decrypt

        public static byte[] DecryptUserKey(byte[] userLicenceKey, byte[] deviceKey, byte[] entropy)
        {
            //    userkey = AES.new(keykey, AES.MODE_CBC).decrypt(userkey)
            //    userkey = userkey[26:-ord(userkey[-1])]
            //    with open(keypath, 'wb') as f:
            //        f.write(userkey)
            //    return True

            if ( entropy == null )
            {
                // entropy = new EntropySource().Entropy;
            }

            byte[] raw_decrypt = Decrypt(userLicenceKey, deviceKey, entropy);

            int mystery = (int)raw_decrypt[raw_decrypt.Length - 1];

            int first = 26;
            int last = raw_decrypt.Length - mystery;

            byte[] res = new byte[last - first];
            Array.Copy(raw_decrypt, res, last - first);

            return res;
        }

        private static byte[] Decrypt(byte[] encrypted_data, byte[] key, byte[] entropy)
        {
            return Decrypt<RijndaelManaged>(encrypted_data, key, entropy);
        }
        private static byte[] Decrypt<T>(byte[] encrypted_data, byte[] key, byte[] entropy) where T : SymmetricAlgorithm, new()
        {
            byte[] decrypted;
            int decryptedByteCount = 0;

            using (T cipher = new T())
            {
                cipher.Mode = CipherMode.CBC;
                // cipher.BlockSize = 8 * entropy.Length;
                cipher.IV = entropy ?? new byte[cipher.BlockSize/8];
                cipher.Key = key;

                using (ICryptoTransform decryptor = cipher.CreateDecryptor())
                {
                    using (MemoryStream from = new MemoryStream(encrypted_data))
                    {
                        using (CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read))
                        {
                            decrypted = new byte[encrypted_data.Length];
                            decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);

                            if (decryptedByteCount == decrypted.Length)
                                return decrypted;

                            byte[] d2 = new byte[decryptedByteCount];
                            Array.Copy(decrypted, d2, decryptedByteCount);
                            return d2;
                        }
                    }
                }
            }
        }

        #endregion
    }
}
