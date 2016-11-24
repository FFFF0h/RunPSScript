//
//  RunPSScriptEngine.cs
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

using System.Processes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading;
using System.IO.Pipes;
using System.Net;
using System.Reflection;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Management;
using System.Security.Principal;
using System.Globalization;
using System.Security.Processes;
using System.Security.AccessControl;


namespace RunPSScript
{
    /// <summary>
    /// PS Script Engine.
    /// </summary>
    public class RunPSScriptEngine : IDisposable
    {
        /// <summary>
        /// Internal stage.
        /// </summary>
        private enum StageType
        {
            None = -1,
            PowerShell = 1,
            Elevated,
            Credential
        }

        private const string NAMEDPIPES_NAME = "!#__PROCESS_RUNNER__";
        private const string NAMEDPIPES_PASSKEY = "Welcome!";
        private const string NAMEDPIPES_EXITCODE = "!#__PROCESS_EXIT__";
        private const string GETSCRIPT_CMD = "GetScript";
        private const int EXITCODE_OK = 0;
        private const int EXITCODE_KO = 1;

        private int _childPID = 0;
        private bool _debug = false;

        #region Properties
        /// <summary>
        /// Gets or sets a value indicating whether the process has exited.
        /// </summary>
        /// <value>
        /// <c>true</c> if the process has exited; otherwise, <c>false</c>.
        /// </value>
        public bool HasExited
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the exit code of the process.
        /// </summary>
        /// <value>
        /// The exit code.
        /// </value>
        public int ExitCode
        {
            get;
            private set;
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="RunPSScriptEngine"/> class.
        /// </summary>
        public RunPSScriptEngine()
        {
            ExitCode = EXITCODE_OK;
            HasExited = false;
        }
        #endregion

        /// <summary>
        /// Runs the Powershell Script Engine.
        /// </summary>
        /// <param name="options">The options parameters.</param>
        /// <returns>Exit code</returns>
        public int Run(string[] options)
        {
            Console.OutputEncoding = Encoding.ASCII;
            FileVersionInfo fvi = GetFileVersionInfo();

            bool silent = false;

            try
            {
                NetworkCredential credential = null;
                int version = 2;
                string domain = null;
                string userName = null;
                SecureString password = null;
                string script = null;
                bool isElevated = false;
                int schedule = -1;
                int processId = Process.GetCurrentProcess().Id;
                bool passthrough = false;
                bool hash = false;
                bool nologo = false;
                StageType stage = StageType.None;

                // Gets CLI arguments.
                for (int i = 0; i < options.Length; i++)
                {
                    string arg = options[i];
                    if (arg.StartsWith("-"))
                    {
                        switch (arg.ToLowerInvariant())
                        {
                            case "-hash":
                                password = GetArgumentValue(options, ref i).ConvertToSecureString();
                                hash = true;
                                break;
                            case "-script":
                                script = GetArgumentValue(options, ref i);
                                break;
                            case "-version":
                                version = Convert.ToInt32(GetArgumentValue(options, ref i));
                                break;
                            case "-domain":
                                domain = StringCipher.Decrypt(GetArgumentValue(options, ref i), GetUniqueIdentifier());
                                break;
                            case "-username":
                                userName = StringCipher.Decrypt(GetArgumentValue(options, ref i), GetUniqueIdentifier());
                                break;
                            case "-password":
                                password = StringCipher.Decrypt(GetArgumentValue(options, ref i), GetUniqueIdentifier()).ConvertToSecureString();
                                break;
                            case "-elevated":
                                isElevated = true;
                                break;
                            case "-schedule":
                                double s = Convert.ToDouble(GetArgumentValue(options, ref i), CultureInfo.InvariantCulture) * 60 * 1000;
                                if (s > Int32.MaxValue)
                                    schedule = Int32.MaxValue;
                                else if (s == 0)
                                    schedule = 500;
                                else
                                    schedule = (int)s;
                                break;
                            case "-pid":
                                processId = Convert.ToInt32(GetArgumentValue(options, ref i));
                                passthrough = true;
                                break;
                            case "-stage":
                                stage = (StageType)Enum.Parse(typeof(StageType), GetArgumentValue(options, ref i));
                                break;
                            case "-silent":
                                silent = true;
                                break;
                            case "-debug":
                                _debug = true;
                                break;
                            case "-nologo":
                                nologo = true;
                                break;
                            case "-help":
                                PrintHeader();
                                PrintNotice();
                                return 0;
                            default:
                                PrintHeader();
                                Console.WriteLine("Wrong argument: {0}", arg);
                                PrintWarning();
                                return EXITCODE_KO;
                        }
                    }
                }

                Log("START " + fvi.ProductName.ToUpperInvariant() + " v" + fvi.FileVersion + " WITH PID #" + Process.GetCurrentProcess().Id);
                Log("ARGS       : " + string.Join(" ", options));

                // Script parameters is requiered !
                if (string.IsNullOrEmpty(script) && !passthrough && !hash)
                {
                    PrintHeader();
                    Console.WriteLine("Script parameter is required !");
                    PrintWarning();
                    return EXITCODE_KO;
                }

                // Show Copyright banner.
                if (!nologo)
                    PrintHeader();

                // Hash password.
                if (hash)
                {
                    // Get system UID
                    string k = StringCipher.Encrypt(password.ConvertToUnsecureString(), GetUniqueIdentifier());
                    Console.WriteLine(k);
                    return EXITCODE_OK;
                }

                // Gets user credentials
                if (!string.IsNullOrEmpty(userName))
                {
                    // WTF! .Net 3.5 does not implements the creation of ICredentials with a SecureString. MS are you serious ?
                    if (!string.IsNullOrEmpty(domain))
                        credential = new NetworkCredential(userName, password.ConvertToUnsecureString(), domain);
                    else
                        credential = new NetworkCredential(userName, password.ConvertToUnsecureString());
                }

                // Check if the current process already runs with elevated privileges
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (isElevated)
                {
                    if (UAC.IsProcessElevated)
                    {
                        // removes elevated mode
                        options = GetFilteredParameters(options, new[] { "-elevated" }, null).ToArray();
                        isElevated = false;
                        Log("UAC        : Elevation not needed");
                    }
                    else
                    {
                        Log("UAC        : Need elevation");
                    }
                }

                // Encode pipeline for use in PS if any.
                if (IsPipedInput() && !passthrough)
                {
                    string pipe = Console.In.ReadToEnd();
                    if (!string.IsNullOrEmpty(pipe))
                    {
                        Log("READ PIPE  :\n" + pipe);
                        StringBuilder s = new StringBuilder();
                        s.AppendFormat("\"{0}\"", Convert.ToBase64String(Encoding.Unicode.GetBytes(pipe)));
                        s.Append("|%{[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($_))}|" + script);
                        script = s.ToString();
                    }
                }

                // Stage Logic
                if (stage == StageType.None)
                {
                    if (!string.IsNullOrEmpty(userName))
                        stage = StageType.Credential;
                    else if (isElevated)
                        stage = StageType.Elevated;
                    else
                        stage = StageType.PowerShell;
                }

                // Starts named pipes server for communication with the child process
                NamedPipeServer<String> server = null;
                if (stage != StageType.PowerShell)
                {
                    if (!passthrough)
                    {
                        server = GetNamePipeServer(script, processId);
                        server.Start();
                    }
                }

                // Starts the child processes loop.
                do
                {
                    try
                    {
                        Log("STAGE      : " + ((int)stage).ToString() + " - " + stage.ToString());
                        Log("PASSTHRU   : " + passthrough.ToString());
                        switch (stage)
                        {
                            case StageType.Credential:
                                {
                                    // Construct child process arguments
                                    string[] switchParamToRemoves = { "-help" };
                                    string[] keyPairParamToRemoves = { "-domain", "-username", "-password", "-script", "-schedule", "-stage" };
                                    List<string> param = GetFilteredParameters(options, switchParamToRemoves, keyPairParamToRemoves);

                                    // Add PID identifier for named pipe communication
                                    if (!passthrough)
                                    {
                                        param.Add("-pid");
                                        param.Add(processId.ToString());
                                    }

                                    Log("ARGS CHILD : " + string.Join(" ", param.ToArray()));

                                    // Starts child process of myself with credentials: .Net Process class failed to start a process with custom credentials when running under LocalSystem account.
                                    if (WindowsIdentity.GetCurrent().Name.ToLowerInvariant() == "nt authority\\system")
                                    {
                                        RunSelfProcessInLocalSystem(param, credential);
                                    }
                                    else
                                    {
                                        RunSelfProcess(param, false, credential);
                                    }

                                    Thread.Sleep(1000);

                                    break;
                                }
                            case StageType.Elevated:
                                {
                                    // Construct child process arguments
                                    string[] switchParamToRemoves = { "-elevated", "-help" };
                                    string[] keyPairParamToRemoves = { "-script", "-schedule", "-stage" };
                                    List<string> param = GetFilteredParameters(options, switchParamToRemoves, keyPairParamToRemoves);

                                    // Add PID identifier
                                    if (!passthrough)
                                    {
                                        param.Add("-pid");
                                        param.Add(processId.ToString());
                                    }

                                    Log("ARGS CHILD : " + string.Join(" ", param.ToArray()));

                                    // Starts child process of myself with elevated privileges
                                    RunSelfProcess(param, isElevated, credential);
                                    Thread.Sleep(1000);

                                    break;
                                }
                            case StageType.PowerShell:
                                {
                                    // Starts named pipes client for communication with the parent process.
                                    NamedPipeClient<String> client = null;
                                    if (passthrough)
                                    {
                                        client = GetNamedPipeClientAndWaitForConnection(processId, out script);
                                    }

                                    // Runs the PS process
                                    //WindowsStationAndDesktop.GrantAccess(credential.UserName);

                                    using (new PrivilegeEnabler(Process.GetCurrentProcess(), Privilege.AssignPrimaryToken, Privilege.IncreaseQuota, Privilege.TrustedComputerBase))
                                    using (ScriptRunner ps = new ScriptRunner(ScriptEngine.Language.PowerShell, credential, isElevated, script))
                                    {
                                        ps.OutputReceived += (o, e) =>
                                            {
                                                if (passthrough)
                                                    client.PushMessage(e.Data);
                                                else
                                                    Console.WriteLine(e.Data);

                                                Log("PS         : " + e.Data);
                                            };
                                        ps.ProcessExited += (o, e) =>
                                            {
                                                ExitCode = e.ExitCode;
                                                if (passthrough)
                                                    client.PushMessage(NAMEDPIPES_EXITCODE + e.ExitCode);
                                            };

                                        ps.Run(new[] { "-V", version.ToString() });
                                    }

                                    Thread.Sleep(1000);

                                    if (passthrough)
                                        client.Stop();

                                    break;
                                }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (!silent)
                            Console.WriteLine("ERROR: {0}", ex.ToString());
                        Log("ERROR      : " + ex.ToString());
                    }

                    // Wait the schedule time
                    if (schedule != -1)
                        Thread.Sleep(schedule);

                } while (schedule != -1);

                // Stops the pipe server
                if (server != null && !passthrough)
                    server.Stop();
            }
            catch (Exception ex)
            {
                if (!silent)
                    Console.WriteLine("ERROR: {0}", ex.ToString());
                Log("ERROR      : " + ex.ToString());
            }

            Log("EXIT CODE  : " + ExitCode);
            Log("STOP " + fvi.ProductName.ToUpperInvariant() + " v" + fvi.FileVersion + " WITH PID #" + Process.GetCurrentProcess().Id);

            return ExitCode;
        }

        #region Privates
        /// <summary>
        /// Determines whether the input is piped.
        /// </summary>
        /// <returns></returns>
        private bool IsPipedInput()
        {
            try
            {
                bool isKey = Console.KeyAvailable;
                return false;
            }
            catch
            {
                return true;
            }
        }

        /// <summary>
        /// Gets the filtered parameters.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="switchParamToRemoves">The switch parameter to removes.</param>
        /// <param name="keyPairParamToRemoves">The key pair parameter to removes.</param>
        /// <returns>A list of parameters filtered.</returns>
        private List<string> GetFilteredParameters(string[] options, string[] switchParamToRemoves, string[] keyPairParamToRemoves)
        {
            List<string> param = new List<string>();
            for (int i = 0; i < options.Length; i++)
            {
                // Removes key/pair script parameters
                if (keyPairParamToRemoves != null && keyPairParamToRemoves.Contains(options[i].ToLowerInvariant()))
                {
                    GetArgumentValue(options, ref i);
                }
                // Removes switch script parameters
                else if (switchParamToRemoves != null && switchParamToRemoves.Contains(options[i].ToLowerInvariant()))
                {
                    // Nothing to do
                }
                // Adds all others parameters
                else
                {
                    param.Add(options[i]);
                }
            }

            return param;
        }

        /// <summary>
        /// Gets the argument value.
        /// </summary>
        /// <param name="arguments">The arguments.</param>
        /// <param name="i">The i.</param>
        /// <returns></returns>
        private string GetArgumentValue(string[] arguments, ref int i)
        {
            StringBuilder sb = new StringBuilder();
            for (int j = i + 1; j < arguments.Length; j++)
            {
                if (arguments[j].StartsWith("-"))
                {
                    i = j - 1;
                    return sb.ToString();
                }
                else
                {
                    sb.Append(arguments[j] + " ");
                }
            }

            i = arguments.Length;
            return sb.ToString();
        }

        /// <summary>
        /// Gets the unique identifier.
        /// </summary>
        /// <returns></returns>
        private string GetUniqueIdentifier()
        {
            string sn = string.Empty;
            using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
            {
                foreach (ManagementObject mo in mos.Get())
                {
                    sn = mo["SerialNumber"].ToString();
                    break;
                }
            }

            return sn;
        }

        /// <summary>
        /// Gets the Named Pipe Server.
        /// </summary>
        /// <param name="script">The script to push.</param>
        /// <param name="channelId">The named pipe channel identifier to use.</param>
        /// <returns>The named pipe server.</returns>
        private NamedPipeServer<String> GetNamePipeServer(string script, int channelId)
        {
            NamedPipeServer<String> server = new NamedPipeServer<String>(NAMEDPIPES_NAME + channelId);
            server.ClientConnected += (connection) =>
            {
                connection.PushMessage(NAMEDPIPES_PASSKEY);
            };
            server.ClientDisconnected += (connection) =>
            {
                HasExited = true;
            };
            server.ClientMessage += (connection, message) =>
            {
                Log("RECV MSG   : " + message);
                if (message.StartsWith(NAMEDPIPES_EXITCODE))
                {
                    ExitCode = Convert.ToInt32(message.Remove(0, NAMEDPIPES_EXITCODE.Length));
                    HasExited = true;
                }
                else if (message == GETSCRIPT_CMD)
                {
                    connection.PushMessage(script);
                }
                else
                {
                    Console.WriteLine(message);
                }
            };
            server.Error += (exception) =>
            {
                throw exception;
            };

            return server;
        }

        /// <summary>
        /// Starts the and waits the named pipe client to connect to the server.
        /// </summary>
        /// <param name="channelId">The channel identifier to use.</param>
        /// <param name="script">The script transmitted by the server.</param>
        /// <returns>The named pipe client.</returns>
        private NamedPipeClient<String> GetNamedPipeClientAndWaitForConnection(int channelId, out string script)
        {
            string sc = null;
            bool handshake = false;
            NamedPipeClient<String> client = new NamedPipeClient<String>(NAMEDPIPES_NAME + channelId);
            client.ServerMessage += (connection, message) =>
            {
                Log("RECV MSG   : " + message);
                if (message == NAMEDPIPES_PASSKEY)
                {
                    handshake = true;
                }
                else if (!handshake)
                {
                    throw new System.IO.IOException("Named pipes invalid passkey !");
                }
                else
                {
                    sc = message;
                }
            };
            client.Error += (exception) =>
            {
                throw exception;
            };
            client.Start();

            // Wait for client to connect to the server
            while (!handshake)
            {
                Thread.Sleep(100);
            }

            // Get script from server
            client.PushMessage(GETSCRIPT_CMD);
            Log("SEND MSG   : " + GETSCRIPT_CMD);
            while (string.IsNullOrEmpty(sc))
            {
                Thread.Sleep(100);
            }

            script = sc;
            return client;
        }


        /// <summary>
        /// Runs the self process in in local system credential.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="credential">The credential.</param>
        private void RunSelfProcessInLocalSystem(List<string> parameters, NetworkCredential credential)
        {
            WindowsStationAndDesktop.GrantAccess(credential.UserName);

            using (new PrivilegeEnabler(Process.GetCurrentProcess(), Privilege.AssignPrimaryToken, Privilege.IncreaseQuota, Privilege.TrustedComputerBase))
            using (WindowsImpersonation imp = new WindowsImpersonation(credential.Domain, credential.UserName, credential.Password.ConvertToSecureString()))
            {
                _childPID = imp.RunCommand(System.Reflection.Assembly.GetEntryAssembly().Location, " " + string.Join(" ", parameters.ToArray()), Environment.CurrentDirectory, false).Id;
            }
            Log("PID CHILD  : " + _childPID);

            // Wait until child process exit.
            HasExited = false;
            while (!HasExited)
            {
                // Check if the process has exited
                try
                {
                    Process.GetProcessById(_childPID);
                }
                catch
                {
                    HasExited = true;
                }

                Thread.Sleep(100);
            }
        }

        /// <summary>
        /// Runs the self process.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="isElevated">if set to <c>true</c> runs with elevated privileges.</param>
        /// <param name="credential">The credentials.</param>
        private void RunSelfProcess(List<string> parameters, bool isElevated, NetworkCredential credential)
        {
            string exePath = System.Reflection.Assembly.GetEntryAssembly().Location;
            
            //WindowsStationAndDesktop.GrantAccess(credential.UserName);

            using (new PrivilegeEnabler(Process.GetCurrentProcess(), Privilege.AssignPrimaryToken, Privilege.IncreaseQuota, Privilege.TrustedComputerBase))
            using (ScriptRunner child = new ScriptRunner(ScriptEngine.Language.Exe, credential, isElevated, exePath))
            {
                // Fire self child process
                child.Start(parameters.ToArray());

                // Saves child PID for killing 
                _childPID = child.ProcessRunner.PID;
                Log("PID CHILD  : " + _childPID);

                // Wait until child process exit.
                HasExited = false;
                while (!HasExited)
                {
                    // Check if the process has exited
                    try
                    {
                        Process.GetProcessById(_childPID);
                    }
                    catch
                    {
                        HasExited = true;
                    }

                    Thread.Sleep(100);
                }
                //child.ProcessRunner.Kill();
            }
        }
        #endregion

        #region Log to file
        private static readonly object _lock = new object();

        /// <summary>
        /// Logs the specified message.
        /// </summary>
        /// <param name="message">The message.</param>
        private void Log(string message)
        {
            if (_debug)
            {
                lock (_lock)
                {
                    try
                    {
                        string data = string.Format("[{0}] {1}: {2}", DateTime.UtcNow.ToString("o"), Process.GetCurrentProcess().Id.ToString("D5"), message);
                        Debug.WriteLine(data);

                        string path = Assembly.GetExecutingAssembly().CodeBase.Replace("file:///", string.Empty);
                        using (StreamWriter writer = new StreamWriter(path + ".log", true))
                        {
                            writer.WriteLine(data);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("ERROR: " + ex.ToString());
                    }
                }
            }
        }
        #endregion

        #region Print Header
        /// <summary>
        /// Gets the assembly file version information.
        /// </summary>
        /// <returns></returns>
        private FileVersionInfo GetFileVersionInfo()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            return FileVersionInfo.GetVersionInfo(assembly.Location);
        }

        /// <summary>
        /// Prints the header.
        /// </summary>
        private void PrintHeader()
        {
            FileVersionInfo fvi = GetFileVersionInfo();
            Console.WriteLine("{0} - {1} - v{2}", fvi.InternalName, fvi.Comments, fvi.FileVersion);
            Console.WriteLine("{0}", fvi.LegalCopyright.Replace("©", "(c)"));
            Console.WriteLine();
        }

        /// <summary>
        /// Prints the notice.
        /// </summary>
        private void PrintNotice()
        {
            FileVersionInfo fvi = GetFileVersionInfo();
            Console.WriteLine("Usage:");
            Console.WriteLine("echo hi | {0} -Script .\\hello.ps1 [-Version (1|2|3)] [-Domain HashedADSLOCAL] [-UserName HashedJohn] [-Password HashedPwd] [-Elevated] [-Schedule 10] [-Silent] [-Debug]", fvi.InternalName);
            Console.WriteLine("{0} -Hash V3ryS3cureP4sswOrd", fvi.InternalName);
            Console.WriteLine("With:");
            Console.WriteLine("\t-Script\t\tThe PS script or command. Required.");
            Console.WriteLine("\t-Version\tPowershell version 1, 2 or 3. Default is 2.");
            Console.WriteLine("\t-Domain\t\tHashed account domain name used to run the command.");
            Console.WriteLine("\t-UserName\tHashed account user name used to run the command.");
            Console.WriteLine("\t-Password\tHashed account password used to run the command.");
            Console.WriteLine("\t-Elevated\tRuns the command with elevated privileges.");
            Console.WriteLine("\t-Schedule\tExecutes the command every x.x minutes.");
            Console.WriteLine("\t-Silent\t\tDo not show any error messages.");
            Console.WriteLine("\t-Debug\t\tCreate a log file containing debug informations.");
            Console.WriteLine("\t-NoLogo\t\tStarts without displaying the copyright banner.");
            Console.WriteLine("\t-Hash\t\tGenerate a system unique hashed string.");

        }

        /// <summary>
        /// Prints the warning.
        /// </summary>
        private void PrintWarning()
        {
            FileVersionInfo fvi = GetFileVersionInfo();
            Console.WriteLine("Type {0} -help to display the help notice.", fvi.InternalName);
        }
        #endregion

        #region Dispose
        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        void IDisposable.Dispose()
        {
            Log("DISPOSING  : " + Process.GetCurrentProcess().Id);
            if (_childPID != 0)
            {
                try
                {
                    Process p = Process.GetProcessById(_childPID);
                    if (p != null)
                    {
                        p.Close();
                        Thread.Sleep(1000);
                        if (!p.HasExited)
                        {
                            Log("KILL PROC  : " + _childPID);
                            p.Kill();
                        }
                    }
                }
                catch
                {

                }
            }
        }
        #endregion
    }
}
