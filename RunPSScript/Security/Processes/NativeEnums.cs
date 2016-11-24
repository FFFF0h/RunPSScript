// <copyright file="NativeEnums.cs" company="Nick Lowe">
// Copyright © Nick Lowe 2009
// </copyright>
// <author>Nick Lowe</author>
// <email>nick@int-r.net</email>
// <url>http://processprivileges.codeplex.com/</url>

namespace System.Security.Processes
{
    using System;
    using System.Diagnostics.CodeAnalysis;

    /// <summary>
    ///     <para>Privilege attributes that augment a <see cref="Privilege"/> with state information.</para>
    /// </summary>
    /// <remarks>
    ///     <para>Use the following checks to interpret privilege attributes:</para>
    ///     <para>
    ///         <c>// Privilege is disabled.<br/>if (attributes == PrivilegeAttributes.Disabled) { /* ... */ }</c>
    ///     </para>
    ///     <para>
    ///         <c>// Privilege is enabled.<br/>if ((attributes &amp; PrivilegeAttributes.Enabled) == PrivilegeAttributes.Enabled) { /* ... */ }</c>
    ///     </para>
    ///     <para>
    ///         <c>// Privilege is removed.<br/>if ((attributes &amp; PrivilegeAttributes.Removed) == PrivilegeAttributes.Removed) { /* ... */ }</c>
    ///     </para>
    ///     <para>To avoid having to work with a flags based enumerated type, use <see cref="ProcessExtensions.GetPrivilegeState(PrivilegeAttributes)"/> on attributes.</para>
    /// </remarks>
    [Flags,
    SuppressMessage(
        "Microsoft.Design",
        "CA1008:EnumsShouldHaveZeroValue",
        Justification = "Native enum."),
    SuppressMessage(
        "Microsoft.Usage",
        "CA2217:DoNotMarkEnumsWithFlags",
        Justification = "Native enum.")]
    public enum PrivilegeAttributes
    {
        /// <summary>Privilege is disabled.</summary>
        Disabled = 0,

        /// <summary>Privilege is enabled by default.</summary>
        EnabledByDefault = 1,

        /// <summary>Privilege is enabled.</summary>
        Enabled = 2,

        /// <summary>Privilege is removed.</summary>
        Removed = 4,

        /// <summary>Privilege used to gain access to an object or service.</summary>
        UsedForAccess = -2147483648
    }

    /// <summary>Access rights for access tokens.</summary>
    [Flags,
    SuppressMessage(
        "Microsoft.Design",
        "CA1008:EnumsShouldHaveZeroValue",
        Justification = "Native enum."),
    SuppressMessage("Microsoft.Usage",
        "CA2217:DoNotMarkEnumsWithFlags",
        Justification = "Native enum.")]
    public enum TokenAccessRights
    {
        /// <summary>Right to attach a primary token to a process.</summary>
        AssignPrimary = 0x0001,

        /// <summary>Right to duplicate an access token.</summary>
        Duplicate = 0x0002,

        /// <summary>Right to attach an impersonation access token to a process.</summary>
        Impersonate = 0x0004,

        /// <summary>Right to query an access token.</summary>
        Query = 0x0008,

        /// <summary>Right to query the source of an access token.</summary>
        QuerySource = 0x0010,

        /// <summary>Right to enable or disable the privileges in an access token.</summary>
        AdjustPrivileges = 0x0020,

        /// <summary>Right to adjust the attributes of the groups in an access token.</summary>
        AdjustGroups = 0x0040,

        /// <summary>Right to change the default owner, primary group, or DACL of an access token.</summary>
        AdjustDefault = 0x0080,

        /// <summary>Right to adjust the session ID of an access token.</summary>
        AdjustSessionId = 0x0100,

        /// <summary>Combines all possible access rights for a token.</summary>
        AllAccess = AccessTypeMasks.StandardRightsRequired |
            AssignPrimary |
            Duplicate |
            Impersonate |
            Query |
            QuerySource |
            AdjustPrivileges |
            AdjustGroups |
            AdjustDefault |
            AdjustSessionId,

        /// <summary>Combines the standard rights required to read with <see cref="Query"/>.</summary>
        Read = AccessTypeMasks.StandardRightsRead |
            Query,

        /// <summary>Combines the standard rights required to write with <see cref="AdjustDefault"/>, <see cref="AdjustGroups"/> and <see cref="AdjustPrivileges"/>.</summary>
        Write = AccessTypeMasks.StandardRightsWrite |
            AdjustPrivileges |
            AdjustGroups |
            AdjustDefault,

        /// <summary>Combines the standard rights required to execute with <see cref="Impersonate"/>.</summary>
        Execute = AccessTypeMasks.StandardRightsExecute |
            Impersonate
    }

    [Flags]
    internal enum AccessTypeMasks
    {
        Delete = 65536,

        ReadControl = 131072,

        WriteDAC = 262144,

        WriteOwner = 524288,

        Synchronize = 1048576,

        StandardRightsRequired = 983040,

        StandardRightsRead = ReadControl,

        StandardRightsWrite = ReadControl,

        StandardRightsExecute = ReadControl,

        StandardRightsAll = 2031616,

        SpecificRightsAll = 65535
    }

    internal enum TokenInformationClass
    {
        None,
        TokenUser,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
    }

    [Flags]
    enum CREATE_PROCESS_FLAGS
    {
        CREATE_BREAKAWAY_FROM_JOB           = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE           = 0x04000000,
        CREATE_NEW_CONSOLE                  = 0x00000010,
        CREATE_NEW_PROCESS_GROUP            = 0x00000200,
        CREATE_NO_WINDOW                    = 0x08000000,
        CREATE_PROTECTED_PROCESS            = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL    = 0x02000000,
        CREATE_SEPARATE_WOW_VDM             = 0x00000800,
        CREATE_SHARED_WOW_VDM               = 0x00001000,
        CREATE_SUSPENDED                    = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT          = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS             = 0x00000002,
        DEBUG_PROCESS                       = 0x00000001,
        DETACHED_PROCESS                    = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT        = 0x00080000,
        INHERIT_PARENT_AFFINITY             = 0x00010000
    }

    public enum LogonType
    {
        /// <summary>
        /// This logon type is intended for users who will be interactively using the computer, such as a user being logged on  
        /// by a terminal server, remote shell, or similar process.
        /// This logon type has the additional expense of caching logon information for disconnected operations;
        /// therefore, it is inappropriate for some client/server applications,
        /// such as a mail server.
        /// </summary>
        LOGON32_LOGON_INTERACTIVE = 2,

        /// <summary>
        /// This logon type is intended for high performance servers to authenticate plaintext passwords.

        /// The LogonUser function does not cache credentials for this logon type.
        /// </summary>
        LOGON32_LOGON_NETWORK = 3,

        /// <summary>
        /// This logon type is intended for batch servers, where processes may be executing on behalf of a user without
        /// their direct intervention. This type is also for higher performance servers that process many plaintext
        /// authentication attempts at a time, such as mail or Web servers.
        /// The LogonUser function does not cache credentials for this logon type.
        /// </summary>
        LOGON32_LOGON_BATCH = 4,

        /// <summary>
        /// Indicates a service-type logon. The account provided must have the service privilege enabled.
        /// </summary>
        LOGON32_LOGON_SERVICE = 5,

        /// <summary>
        /// This logon type is for GINA DLLs that log on users who will be interactively using the computer.
        /// This logon type can generate a unique audit record that shows when the workstation was unlocked.
        /// </summary>
        LOGON32_LOGON_UNLOCK = 7,

        /// <summary>
        /// This logon type preserves the name and password in the authentication package, which allows the server to make
        /// connections to other network servers while impersonating the client. A server can accept plaintext credentials
        /// from a client, call LogonUser, verify that the user can access the system across the network, and still
        /// communicate with other servers.
        /// NOTE: Windows NT:  This value is not supported.
        /// </summary>
        LOGON32_LOGON_NETWORK_CLEARTEXT = 8,

        /// <summary>
        /// This logon type allows the caller to clone its current token and specify new credentials for outbound connections.
        /// The new logon session has the same local identifier but uses different credentials for other network connections.
        /// NOTE: This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider.
        /// NOTE: Windows NT:  This value is not supported.
        /// </summary>
        LOGON32_LOGON_NEW_CREDENTIALS = 9,
    }

    public enum LogonProvider
    {
        /// <summary>
        /// Use the standard logon provider for the system.
        /// The default security provider is negotiate, unless you pass NULL for the domain name and the user name
        /// is not in UPN format. In this case, the default provider is NTLM.
        /// NOTE: Windows 2000/NT:   The default security provider is NTLM.
        /// </summary>
        LOGON32_PROVIDER_DEFAULT = 0,
        LOGON32_PROVIDER_WINNT35 = 1,
        LOGON32_PROVIDER_WINNT40 = 2,
        LOGON32_PROVIDER_WINNT50 = 3
    }

    [Flags]
    public enum STARTF : uint
    {
        STARTF_USESHOWWINDOW    = 0x00000001,
        STARTF_USESIZE          = 0x00000002,
        STARTF_USEPOSITION      = 0x00000004,
        STARTF_USECOUNTCHARS    = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_RUNFULLSCREEN    = 0x00000020,  // ignored for non-x86 platforms
        STARTF_FORCEONFEEDBACK  = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
        STARTF_USESTDHANDLES    = 0x00000100,
    }

    public enum ShowWindowCommands : uint
    {
        /// <summary>
        ///        Hides the window and activates another window.
        /// </summary>
        SW_HIDE = 0,

        /// <summary>
        ///        Activates and displays a window. If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when displaying the window for the first time.
        /// </summary>
        SW_SHOWNORMAL = 1,

        /// <summary>
        ///        Activates and displays a window. If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when displaying the window for the first time.
        /// </summary>
        SW_NORMAL = 1,

        /// <summary>
        ///        Activates the window and displays it as a minimized window.
        /// </summary>
        SW_SHOWMINIMIZED = 2,

        /// <summary>
        ///        Activates the window and displays it as a maximized window.
        /// </summary>
        SW_SHOWMAXIMIZED = 3,

        /// <summary>
        ///        Maximizes the specified window.
        /// </summary>
        SW_MAXIMIZE = 3,

        /// <summary>
        ///        Displays a window in its most recent size and position. This value is similar to <see cref="ShowWindowCommands.SW_SHOWNORMAL"/>, except the window is not activated.
        /// </summary>
        SW_SHOWNOACTIVATE = 4,

        /// <summary>
        ///        Activates the window and displays it in its current size and position.
        /// </summary>
        SW_SHOW = 5,

        /// <summary>
        ///        Minimizes the specified window and activates the next top-level window in the z-order.
        /// </summary>
        SW_MINIMIZE = 6,

        /// <summary>
        ///        Displays the window as a minimized window. This value is similar to <see cref="ShowWindowCommands.SW_SHOWMINIMIZED"/>, except the window is not activated.
        /// </summary>
        SW_SHOWMINNOACTIVE = 7,

        /// <summary>
        ///        Displays the window in its current size and position. This value is similar to <see cref="ShowWindowCommands.SW_SHOW"/>, except the window is not activated.
        /// </summary>
        SW_SHOWNA = 8,

        /// <summary>
        ///        Activates and displays the window. If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when restoring a minimized window.
        /// </summary>
        SW_RESTORE = 9
    }
}