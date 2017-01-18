//
//  WindowsImpersonation.cs
//
//  Author:
//  	Laurent Le Guillermic (https://github.com/FFFF0h)
//
//  Copyright (c) 2016 Laurent Le Guillermic All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Permissions;
using System.Diagnostics;
using System.Security.Authentication;
using System.ComponentModel;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Security.Processes;

namespace System.Security.Principal
{
    /// <summary>
    /// Windows impersonation.
    /// </summary>
    public class WindowsImpersonation : IDisposable
    {
        private WindowsImpersonationContext _impersonationContext;
        private string _userName;

        /// <summary>
        /// Initializes a new instance of the <see cref="WindowsImpersonation"/> class.
        /// </summary>
        /// <param name="domain">The domain.</param>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        /// <exception cref="AuthenticationException">Unable to impersonate user  + domain + \\ + userName</exception>
        public WindowsImpersonation(string domain, string userName, SecureString password)
        {
            if (!ImpersonateUser(domain, userName, password))
            {
                throw new AuthenticationException("Unable to impersonate user " + domain + "\\" + userName);
            }
        }

        /// <summary>
        /// Impersonates the given user.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="domain">The domain.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        private bool ImpersonateUser(string domain, string userName, SecureString password)
        {
            WindowsIdentity tempWindowsIdentity;
            IntPtr token = IntPtr.Zero;
            IntPtr tokenDuplicate = IntPtr.Zero;
            if (NativeMethods.RevertToSelf())
            {
                IntPtr passwordPtr = Marshal.SecureStringToGlobalAllocUnicode(password);
                if (NativeMethods.LogonUser(userName, domain, passwordPtr, (int)LogonType.LOGON32_LOGON_NETWORK, (int)LogonProvider.LOGON32_PROVIDER_DEFAULT, ref token))
                {
                    if (NativeMethods.DuplicateToken(token, 2, ref tokenDuplicate) != 0)
                    {
                        tempWindowsIdentity = new WindowsIdentity(tokenDuplicate);
                        _impersonationContext = tempWindowsIdentity.Impersonate();
                        if (_impersonationContext != null)
                        {
                            _userName = userName;

                            Marshal.ZeroFreeGlobalAllocUnicode(passwordPtr);
                            NativeMethods.CloseHandle(token);
                            NativeMethods.CloseHandle(tokenDuplicate);
                            return true;
                        }
                    }
                }
                Marshal.ZeroFreeGlobalAllocUnicode(passwordPtr);
            }
            if (token != IntPtr.Zero)
                NativeMethods.CloseHandle(token);
            if (tokenDuplicate != IntPtr.Zero)
                NativeMethods.CloseHandle(tokenDuplicate);
            return false;
        }

        /// <summary>
        /// Undoes the impersonation.
        /// </summary>
        private void UndoImpersonation()
        {
            _impersonationContext.Undo();
        }

        /// <summary>
        /// Create an environment
        /// </summary>
        /// <param name="token">The security token</param>
        /// <param name="inherit">Inherit the environment from the calling process</param>
        /// <returns>a dictionary that represents the environ</returns>
        private static Dictionary<string, string> CreateEnvironmentBlock(IntPtr token, bool inherit)
        {
            IntPtr env = IntPtr.Zero;
            if (!NativeMethods.CreateEnvironmentBlock(ref env, token, inherit))
            {
                int lastError = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(lastError, "CreateEnvironmentBlock Error " + lastError);
            }
            Dictionary<String, String> userEnvironment = new Dictionary<string, string>();
            try
            {
                StringBuilder testData = new StringBuilder("");
                unsafe
                {
                    short* start = (short*)env.ToPointer();
                    bool done = false;
                    short* current = start;
                    while (!done)
                    {
                        if ((testData.Length > 0) && (*current == 0) && (current != start))
                        {
                            String data = testData.ToString();
                            int index = data.IndexOf('=');
                            if (index == -1)
                            {
                                userEnvironment.Add(data, "");
                            }
                            else if (index == (data.Length - 1))
                            {
                                userEnvironment.Add(data.Substring(0, index), "");
                            }
                            else
                            {
                                userEnvironment.Add(data.Substring(0, index), data.Substring(index + 1));
                            }
                            testData.Length = 0;
                        }
                        if ((*current == 0) && (current != start) && (*(current - 1) == 0))
                        {
                            done = true;
                        }
                        if (*current != 0)
                        {
                            testData.Append((char)*current);
                        }
                        current++;
                    }
                }
            }
            finally
            {
                NativeMethods.DestroyEnvironmentBlock(env);
            }
            return userEnvironment;
        }
        /// <summary>
        /// Create a byte array that represents the environment for
        /// the different CreateProcess calls
        /// </summary>
        /// <param name="env">The input environment</param>
        /// <returns>A byte array</returns>
        private byte[] CreateEnvironment(Dictionary<string, string> env)
        {
            MemoryStream ms = new MemoryStream();
            StreamWriter w = new StreamWriter(ms, Encoding.Unicode);
            w.Flush();
            ms.Position = 0; //Skip any byte order marks to identify the encoding
            Char nullChar = (char)0;
            foreach (string k in env.Keys)
            {
                w.Write("{0}={1}", k, env[k]);
                w.Write(nullChar);
            }
            w.Write(nullChar);
            w.Write(nullChar);
            w.Flush();
            ms.Flush();
            byte[] data = ms.ToArray();
            return data;
        }

        /// <summary>
        /// Runs a command.
        /// </summary>
        /// <param name="commandFilePath">The command file path.</param>
        /// <param name="commandArguments">The command arguments.</param>
        /// <param name="workingDirectory">The working directory.</param>
        /// <param name="waitForExit">if set to <c>true</c> wait for exit.</param>
        /// <returns>The launched process.</returns>
        /// <exception cref="Exception">Create Process failed.</exception>
        /// <exception cref="Win32Exception">Creation of the process failed.</exception>
        public Process RunCommand(string commandFilePath, string commandArguments, string workingDirectory, bool waitForExit)
        {
            IntPtr token = new IntPtr(0);
            IntPtr dupedToken = new IntPtr(0);
            bool ret;

            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.bInheritHandle = false;
            sa.Length = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = (IntPtr)0;

            token = WindowsIdentity.GetCurrent().Token;

            const int SecurityImpersonation = 2;
            const int TokenType = 1;
            ret = NativeMethods.DuplicateTokenEx(token, (int)TokenAccessRights.AssignPrimary | (int)TokenAccessRights.Duplicate | (int)TokenAccessRights.Query, ref sa, SecurityImpersonation, TokenType, ref dupedToken);

            if (ret == false)
            {
                //NativeMethods.CloseHandle(token);
                NativeMethods.CloseHandle(dupedToken);

                throw new Exception(Marshal.GetLastWin32Error().ToString());
            }

            // Load Profile
            PROFILEINFO pri = new PROFILEINFO();
            pri.dwSize = Marshal.SizeOf(pri);
            pri.lpUserName = _userName;
            pri.dwFlags = 1;
            if (!NativeMethods.LoadUserProfile(dupedToken, ref pri) && pri.hProfile == IntPtr.Zero)
            {
                NativeMethods.CloseHandle(dupedToken);
                throw new Exception(Marshal.GetLastWin32Error().ToString());
            }

            // Process Information
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // Startup Information
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            //if this member is NULL, the new process inherits the desktop
            //and window station of its parent process. If this member is
            //an empty string, the process does not inherit the desktop and
            //window station of its parent process; instead, the system
            //determines if a new desktop and window station need to be created.
            //If the impersonated user already has a desktop, the system uses the
            //existing desktop.
            si.lpDesktop = null;
            //si.lpDesktop = "";

            //si.lpDesktop = @"WinSta0\Default"; //Modify as needed
            //si.dwFlags = (uint)STARTF.STARTF_USESHOWWINDOW | (uint)STARTF.STARTF_FORCEONFEEDBACK;
            //si.wShowWindow = (short)ShowWindowCommands.SW_HIDE;

            IntPtr environmentBlock = IntPtr.Zero;      
            try
            {
                ret = NativeMethods.CreateEnvironmentBlock(ref environmentBlock, token, false);
                if (ret)
                    ret = NativeMethods.CreateProcessAsUser(dupedToken, commandFilePath, commandArguments, ref sa, ref sa, false, (int)CREATE_PROCESS_FLAGS.CREATE_UNICODE_ENVIRONMENT, environmentBlock, workingDirectory, ref si, out pi);
            }
            finally
            {
                if (environmentBlock != IntPtr.Zero)
                    NativeMethods.DestroyEnvironmentBlock(environmentBlock);
            }

            Process p = null;
            if (!ret)
                throw (new Win32Exception("Creation of the process failed with " + Marshal.GetLastWin32Error()));
            else
            {
                try
                {
                    p = Process.GetProcessById((int)pi.dwProcessId);
                    if (waitForExit)
                    {
                        p.WaitForExit();
                    }
                }
                catch
                {

                }
                NativeMethods.CloseHandle(pi.hProcess);
                NativeMethods.CloseHandle(pi.hThread);
            }

            NativeMethods.UnloadUserProfile(token, pri.hProfile);
            //NativeMethods.CloseHandle(token);
            ret = NativeMethods.CloseHandle(dupedToken);
            if (ret == false)
                throw (new Exception(Marshal.GetLastWin32Error().ToString()));

            return p;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            UndoImpersonation();
            _impersonationContext.Dispose();
        }
    }
}