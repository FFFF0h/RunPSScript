//
//  OrdinalCaseInsensitiveComparer.cs
//
//  Author:
//  	Laurent Le Guillermic (https://github.com/FFFF0h)
//
//  Copyright (c) 2016 Laurent Le Guillermic. All rights reserved.
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

namespace System.Collections
{
    public class OrdinalCaseInsensitiveComparer : IComparer
    {
        internal static readonly OrdinalCaseInsensitiveComparer Default = new OrdinalCaseInsensitiveComparer();

        public int Compare(object a, object b)
        {
            string text = a as string;
            string text2 = b as string;
            if (text != null && text2 != null)
            {
                return string.CompareOrdinal(text.ToUpperInvariant(), text2.ToUpperInvariant());
            }
            return Comparer.Default.Compare(a, b);
        }
    }
}