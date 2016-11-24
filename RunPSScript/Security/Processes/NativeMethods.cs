// <copyright file="NativeMethods.cs" company="Nick Lowe">
// Copyright © Nick Lowe 2009
// </copyright>
// <author>Nick Lowe</author>
// <email>nick@int-r.net</email>
// <url>http://processprivileges.codeplex.com/</url>

namespace System.Security.Processes
{
    using System;
    using System.Runtime.ConstrainedExecution;
    using System.Runtime.InteropServices;
    using System.Text;

    /// <summary>Static class containing Win32 native methods.</summary>
    internal static class NativeMethods
    {
        internal const int ErrorInsufficientBuffer = 122;

        private const string AdvApi32 = "advapi32.dll";

        private const string Kernel32 = "kernel32.dll";

        private const string UserEnv = "userenv.dll";

        [DllImport(AdvApi32, SetLastError = true),
        SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AdjustTokenPrivileges(
            [In] AccessTokenHandle accessTokenHandle, 
            [In, MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            [In] ref TokenPrivilege newState,
            [In] int bufferLength,
            [In, Out] ref TokenPrivilege previousState,
            [In, Out] ref int returnLength);

        [DllImport(Kernel32, SetLastError = true),
        ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail),
        SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(
            [In] IntPtr handle);

        [DllImport(AdvApi32, CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LookupPrivilegeName(
           [In] string systemName,
           [In] ref Luid luid,
           [In, Out] StringBuilder name,
           [In, Out] ref int nameLength);

        [DllImport(AdvApi32, CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LookupPrivilegeValue(
            [In] string systemName,
            [In] string name,
            [In, Out] ref Luid luid);

        [DllImport(AdvApi32, SetLastError = true),
        SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetTokenInformation(
            [In] AccessTokenHandle accessTokenHandle,
            [In] TokenInformationClass tokenInformationClass,
            [Out] IntPtr tokenInformation,
            [In] int tokenInformationLength,
            [In, Out] ref int returnLength);

        [DllImport(AdvApi32, SetLastError = true),
        SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenProcessToken(
            [In] ProcessHandle processHandle,
            [In] TokenAccessRights desiredAccess,
            [In, Out] ref IntPtr tokenHandle);

        [DllImport(AdvApi32, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool LogonUser(String username, String domain, IntPtr password, int logonType, int logonProvider, ref IntPtr token);

        [DllImport(AdvApi32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int DuplicateToken(IntPtr hToken, int impersonationLevel, ref IntPtr hNewToken);

        [DllImport(AdvApi32, EntryPoint = "DuplicateTokenEx")]
        internal extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType, int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

        [DllImport(AdvApi32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool RevertToSelf();

        //[DllImport(AdvApi32, EntryPoint = "CloseHandle", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        //internal extern static bool CloseHandle(IntPtr handle);

        [DllImport(AdvApi32, EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        internal extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport(UserEnv, SetLastError = true)]
        internal static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport(UserEnv, SetLastError = true)]
        internal static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport(UserEnv, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

        [DllImport(UserEnv, CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool UnloadUserProfile(IntPtr hToken, IntPtr lpProfileInfo);
    }
}