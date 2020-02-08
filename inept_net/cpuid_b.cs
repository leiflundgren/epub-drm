﻿using System;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Globalization;
using System.Linq;

namespace inept_net
{
    public static class CpuID_b
    {
        [Flags]
        private enum AllocationTypes : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Reset = 0x80000,
            LargePages = 0x20000000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000
        }

        [Flags]
        private enum MemoryProtections : uint
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuartModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [Flags]
        private enum FreeTypes : uint
        {
            Decommit = 0x4000,
            Release = 0x8000
        }

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        private unsafe delegate void CPUID0Delegate(byte* buffer);

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        private unsafe delegate void CPUID1Delegate(byte* buffer);

        public static String GetCpuIdsDesc()
        {
            byte[] cpuid0 = CPUID0();
            byte[] cpuid1 = CPUID1();
            return "CPUID0: " + string.Join(", ", cpuid0.Select(x => x.ToString("X2", CultureInfo.InvariantCulture))) + "\n"
                + "CPUID0: " + new string(System.Text.ASCIIEncoding.ASCII.GetChars(cpuid0)) + "\n"
                + "CPUID1: " + string.Join(", ", cpuid1.Select(x => x.ToString("X2", CultureInfo.InvariantCulture))) + "\n"
                ;
        }

        public static unsafe byte[] CPUID0()
        {
            byte[] buffer = new byte[12];

            if (IntPtr.Size == 4)
            {
                IntPtr p = NativeMethods.VirtualAlloc(
                    IntPtr.Zero,
                    new UIntPtr((uint)x86_CPUID0_INSNS.Length),
                    AllocationTypes.Commit | AllocationTypes.Reserve,
                    MemoryProtections.ExecuteReadWrite);
                try
                {
                    Marshal.Copy(x86_CPUID0_INSNS, 0, p, x86_CPUID0_INSNS.Length);

                    CPUID0Delegate del = (CPUID0Delegate)Marshal.GetDelegateForFunctionPointer(p, typeof(CPUID0Delegate));

                    fixed (byte* newBuffer = &buffer[0])
                    {
                        del(newBuffer);
                    }
                }
                finally
                {
                    NativeMethods.VirtualFree(p, 0, FreeTypes.Release);
                }
            }
            else if (IntPtr.Size == 8)
            {
                IntPtr p = NativeMethods.VirtualAlloc(
                    IntPtr.Zero,
                    new UIntPtr((uint)x64_CPUID0_INSNS.Length),
                    AllocationTypes.Commit | AllocationTypes.Reserve,
                    MemoryProtections.ExecuteReadWrite);
                try
                {
                    Marshal.Copy(x64_CPUID0_INSNS, 0, p, x64_CPUID0_INSNS.Length);

                    CPUID0Delegate del = (CPUID0Delegate)Marshal.GetDelegateForFunctionPointer(p, typeof(CPUID0Delegate));

                    fixed (byte* newBuffer = &buffer[0])
                    {
                        del(newBuffer);
                    }
                }
                finally
                {
                    NativeMethods.VirtualFree(p, 0, FreeTypes.Release);
                }
            }

            return buffer;
        }

        public static unsafe byte[] CPUID1()
        {
            byte[] buffer = new byte[12];

            if (IntPtr.Size == 4)
            {
                IntPtr p = NativeMethods.VirtualAlloc(
                    IntPtr.Zero,
                    new UIntPtr((uint)x86_CPUID1_INSNS.Length),
                    AllocationTypes.Commit | AllocationTypes.Reserve,
                    MemoryProtections.ExecuteReadWrite);
                try
                {
                    Marshal.Copy(x86_CPUID1_INSNS, 0, p, x86_CPUID1_INSNS.Length);

                    CPUID1Delegate del = (CPUID1Delegate)Marshal.GetDelegateForFunctionPointer(p, typeof(CPUID1Delegate));

                    fixed (byte* newBuffer = &buffer[0])
                    {
                        del(newBuffer);
                    }
                }
                finally
                {
                    NativeMethods.VirtualFree(p, 0, FreeTypes.Release);
                }
            }
            else if (IntPtr.Size == 8)
            {
                IntPtr p = NativeMethods.VirtualAlloc(
                    IntPtr.Zero,
                    new UIntPtr((uint)x64_CPUID1_INSNS.Length),
                    AllocationTypes.Commit | AllocationTypes.Reserve,
                    MemoryProtections.ExecuteReadWrite);
                try
                {
                    Marshal.Copy(x64_CPUID1_INSNS, 0, p, x64_CPUID1_INSNS.Length);

                    CPUID1Delegate del = (CPUID1Delegate)Marshal.GetDelegateForFunctionPointer(p, typeof(CPUID1Delegate));

                    fixed (byte* newBuffer = &buffer[0])
                    {
                        del(newBuffer);
                    }
                }
                finally
                {
                    NativeMethods.VirtualFree(p, 0, FreeTypes.Release);
                }
            }

            return buffer;
        }

        private static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr VirtualAlloc(
                IntPtr lpAddress,
                UIntPtr dwSize,
                AllocationTypes flAllocationType,
                MemoryProtections flProtect);

            [DllImport("kernel32")]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool VirtualFree(
                IntPtr lpAddress,
                uint dwSize,
                FreeTypes flFreeType);
        }

        #region ASM
        private static byte[] x86_CPUID0_INSNS = new byte[]
        {
            0x53,                      // push   %ebx
            0x31, 0xc0,                // xor    %eax,%eax
            0x0f, 0xa2,                // cpuid
            0x8b, 0x44, 0x24, 0x08,    // mov    0x8(%esp),%eax
            0x89, 0x18,                // mov    %ebx,0x0(%eax)
            0x89, 0x50, 0x04,          // mov    %edx,0x4(%eax)
            0x89, 0x48, 0x08,          // mov    %ecx,0x8(%eax)
            0x5b,                      // pop    %ebx
            0xc3                       // ret
        };

        private static byte[] x86_CPUID1_INSNS = new byte[]
        {
            0x53,                   // push   %ebx
            0x31, 0xc0,             // xor    %eax,%eax
            0x40,                   // inc    %eax
            0x0f, 0xa2,             // cpuid
            0x5b,                   // pop    %ebx
            0xc3                    // ret
        };

        private static byte[] x64_CPUID0_INSNS = new byte[]
        {
            0x49, 0x89, 0xd8,       // mov    %rbx,%r8
            0x49, 0x89, 0xc9,       // mov    %rcx,%r9
            0x48, 0x31, 0xc0,       // xor    %rax,%rax
            0x0f, 0xa2,             // cpuid
            0x4c, 0x89, 0xc8,       // mov    %r9,%rax
            0x89, 0x18,             // mov    %ebx,0x0(%rax)
            0x89, 0x50, 0x04,       // mov    %edx,0x4(%rax)
            0x89, 0x48, 0x08,       // mov    %ecx,0x8(%rax)
            0x4c, 0x89, 0xc3,       // mov    %r8,%rbx
            0xc3                    // retq
        };

        private static byte[] x64_CPUID1_INSNS = new byte[]
        {
            0x53,                     // push   %rbx
            0x48, 0x31, 0xc0,         // xor    %rax,%rax
            0x48, 0xff, 0xc0,         // inc    %rax
            0x0f, 0xa2,               // cpuid
            0x5b,                     // pop    %rbx
            0xc3                      // retq
        };
        #endregion
    }
}
