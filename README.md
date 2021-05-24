### XSEC
XSEC is a project allowing everyone to study very big part of information about Windows Access Control very quickly and by real life examples. Making access tokens with unlimited number of groups and privileges, adjust privileges, usage of AccessCheckByTypeResultListAndAuditAlarmByHandle function, parsing all data related to Access Control, store all to XML and many more.

The project consists of two main parts: the XSEC library itself and tests made on top of the XSEC library. The XSEC library could be using in any other projects independently. All code was written on pure C++ 17, without any dependencies from any SDK or DDK.

The XSEC project is NOT...
 * ...for completely beginners. In order to understand XSEC you need a knowledge about at least what is SID, ACE, what is token and security descriptor;
 * ...for **hackers**. This project is an educational project, this is not a set of utilities. Yes, it could be using for anything, but it is not intended;

### History Of The XSEC

Long time ago I had started my journey studing security (and Windows security as well). There are many useful books about Windows Access Control, but one part is missing - practise. I saw a number of "test plants" related to Windows Access Security - all of them are about making a big nested three of files/directories plus having a separate Windows domain configured. And even with all this efforts performed I cannot say that any user could study all aspects of Windows Access Control using such "test plants".

So, in order to make studing of Windows Access Control much more productive I propose another way - ability to produce any "access tokens", ability to make any security descriptors and then verify access by using a standard Windows API. By doing this we could make **anything**: emulate a "file tree", emulate a "domain user" with any attributes, control all parameters of each ACE in security descriptor and many-many more! This is all done in scope of XSEC project.

### Features
- Pure C++ 17 only;
- No need for any external sources. No DDK, SDK or external libraries. Only XSEC and standard DLLs already exist on each Windows;
- Ability to make any token, with any number of groups, privileges, user attributes, device attributes and local attributres;
- Ability to make any security descriptors (in absolute or relative form);
- Binary format for CLAIM_SECURITY_ATTRIBUTE_V1 (not documented);
- Binary format for SID type inside CLAIM_SECURITY_ATTRIBUTE_V1 (not documented);
- Binary format for “octet string” type inside CLAIM_SECURITY_ATTRIBUTE_V1 (not documented);
- Native usage of any “ACE conditional expression” right in C++ code;
- Ability to save any XSEC type in XML file and then load it from XML file;
- And many more;

### Example
```cpp
auto [result1, granted_access1, access_status1, granted_access_string1] = check_access(
    L"[MS-DTYP] 2.4.4.17.9 Example 1: Attributes in Simple Form",
    XTOKEN::Create(
        XSID::CurrentUser,
        XSID::Everyone,
        {},
        {},
        std::nullopt,
        std::nullopt,
        std::nullopt,
        {
            {{L"Title", { L"VP" }}}
        }
    ),
    { 
        fiction_owner, 
        {{
            XACCESS_ALLOWED_CALLBACK_ACE(
                XSID::Everyone,
                (DWORD)FILE_ALL_ACCESS,
                XLocal(L"Title") == L"VP"
                //// Comment prev line and uncomment next line if you want to test with data directly from [MS-DTYP]
                //std::nullopt, from_hex_codes("61 72 74 78 f8 0a 00 00 00 54 00 69 00 74 00 6c 00 65 00 10 04 00 00 00 56 00 50 00 80")
            )
        }}
    },
    FILE_ALL_ACCESS
);

Assert::AreEqual(granted_access1[0], (DWORD)FILE_ALL_ACCESS);
```
### Installation
In order to run XSEC tests you would need to use any Windows and any user, but with three privileges enabled. In details installation process described in [**this issue**](https://github.com/YuryStrozhevsky/XSEC/issues/1). In order to correctly run XSEC tests read [**this issue**](https://github.com/YuryStrozhevsky/XSEC/issues/2).

### Tests
Detailed description for all XSEC tests you can find in [**this file**](Tests.MD).

### Documentation
All was written on C++, many tests were made, all open, fill free to inspect. If you need an "additional documentation" then most probably you need to study C++ 17 first or read a good books about Windows Access Control (like Keith Brown's "Windows Security"). Also please read [**this FAQ**](FAQ.MD).

### Useful links
- [**sandbox-attacksurface-analysis-tools**](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)
- [**processhacker**](https://github.com/processhacker/processhacker)
- [**WRK (Windows Research Kit)**](https://github.com/jmcjmmcjc/wrk-v1.2)

### Collaboration
I do think current set of tests could be increased. Fill free to open a "push request" in case you have a good tests for related to Windows Access Control.

### License
XSEC library

Copyright (c) 2021 Yury Strozhevsky <yury@strozhevsky.com>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

