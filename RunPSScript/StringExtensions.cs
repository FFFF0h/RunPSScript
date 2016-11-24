//
//  StringExtensions.cs
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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

internal static class StringExtensions
{
    public static string ConvertToUnsecureString(this SecureString securePassword)
    {
        if (securePassword == null)
            throw new ArgumentNullException("securePassword");

        IntPtr unmanagedString = IntPtr.Zero;
        try
        {
            unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
            return Marshal.PtrToStringUni(unmanagedString);
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
        }
    }

    public static SecureString ConvertToSecureString(this string password)
    {
        if (password == null)
            throw new ArgumentNullException("password");

        unsafe
        {
            fixed (char* passwordChars = password)
            {
                var securePassword = new SecureString(passwordChars, password.Length);
                securePassword.MakeReadOnly();
                return securePassword;
            }
        }
    }
}
