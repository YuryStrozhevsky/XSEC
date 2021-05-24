### XSEC Tests
1. BASIC

    1. The “null DACL”
       
       In case in in security descriptor there is no DACL (SE_DACL_PRESENT flag is not set) then all SIDs allowed (all allowed).
       
    2. Empty DACL
       
       If in security descriptor there is a DACL, but there are no ACEs in there there for such security descriptor no SIDs allowed (all denied).
        1. Empty DACL, but with SeTakeOwnershipPrivilege privilege in token
           Even if security descriptor has “empty DACL” a token with SeTakeOwnershipPrivilege can get at least WRITE_OWNER access to such security descriptor.
        2. Empty DACL, but checking special access rights for owner
           If the user in token is equal with owner from security descriptor then such token can always get access “READ_CONTROL + WRITE_DAC”.
    3. Common denied ACE
       
       In a "common case" denied ACEs must be before "allowed" ACEs and should have non-zero access mask. In the test case “denied ACE” denies access to specific user.
       
    4. Denied ACE after allowed ACE
       
       In case of a wrong ACE order the system access checking function would allow all access because the the function meet allow rule first. In example shows a wrong order of ACEs in DACL.
       
    5. Denied ACE with zero access mask
       
       In case of a correct ACE order but when denied ACE has zero access mask system access cheching function do not count the denied ACE (the denied ACE deny nothing).
       
    6. Denied access for group
       
       In this case there is a "deny rule" for group in token. But the group do not have "SE_GROUP_ENABLED" flag set. That is why access checking would not consider the "deny rule" and will grant full access to the SD.
       
        1. Denied access for group, but with a correct group configuration
           
           In order to not allow any user to disable critical groups the group in token must have at least "SE_GROUP_MANDATORY" flag set. So, in this case we have same configuration as in 1.6, but with correctly configured group in token.

    7. Inheritence in ACE
       
       This example shows a different flags could be set in ACE regarding “inheritence”. Shown that when “INHERIT_ONLY_ACE” flag set then such ACE does not count during access checking process.
       
    8. Using of "Principal Self SID" in ACE
       
       There is a special SID “PrincipalSelf” (S-1-5-10) which acts as a “placeholder” for any other SIDs. Such “substitution” could be done only during access checking process. In this particular case there is a special parameter for “AccessCheckByTypeResultListAndAuditAlarmByHandle” function “PrincipalSelfSid”.
       
    9. Audit: common audit message
       
       In order to generate any audit messages during access checking two requirements should be meet: a) in a process token “SeAuditPrivilege” must be enabled; b) correctly configured “audit ACE” should exist in security descriptor. The example generates audit message in “Security” Windows even log.
       
    10. Audit: missing FAILED_ACCESS_ACE_FLAG flag
        
        Any “audit ACE” could be configured in order to generate messages on “allow” or “deny” results. In this particular example there is “audit ACE” without FAILED_ACCESS_ACE_FLAG. And that is why this ACE would not generate any audit messages.
        
    11. Audit: conditional audit message
        
        This example shows “conditional audit ACE” where checking performed againts “user attribute” from token.
        
2. File example
   
   In this example I shown how to use “default DACL” in token, how “ACE inheritence” works in practice and what values we have as a substitute for “Creator Owner” and “Creator Group” special “placeholder SIDs”. Example uses “filesystem” module from C++ 17. This example consists of following steps:
   - Delete any existing directories with name “inherited”;
   - Make a new directory with name “inherited” and with default DACL;
   - Change DACL for this new directory in order not to have any “inhirited ACEs”;
   - Create a new token with “default DACL” having all possible “placeholder SIDs”;
   - Set the new token as active token to current thread;
   - Make a new subdirectory using this “manually made” token;
   - Make a new file “file1.txt” using this “manually made” token. After the file made system automatically substitute “Creator Owner” on “owner” from token and “Creator Group” on “primary group” from token. Also system automatically append two new ACEs having same “owner” and “group” ACEs, but with data from “process token”;
   - Read and initialize XSEC security descriptor object (XSD) from data from “file1.txt”;
   - Store all security descriptor data to XML file;
   - Restore “default token” to current process;
   - Make a new file “file2.txt”. In this case system also made a sustitution for “Creator Owner” and “Creator Group”, but now all values came from default process token;
3. Integrity check
   
   1. The "null DACL" with low integrity level in token 
      Even if there is “null DACL” in security descriptor (all SIDs allowed), but the seucrity descriptor has higher “mandatory policy level” than a token, the token would not have any access to the security descriptor.
      
     * The 'null DACL' with low integrity level in token but with 'SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0' 
       The “integrity check” performs on base of set of flags in token and in security descriptor. This particular example shows situation when in security descriptor we have “'SYSTEM_MANDATORY_LABEL_NO_READ_UP” flag set to 0 and “desired acces” for access check function is only “FILE_READ_DATA”. In this case “integrity check” mechanism would pass the access request even if “mandatory policy level” in security descriptor is higher than in token.
   
     * The 'null DACL' with low integrity level in token but with 'SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0' but without 'mapping' 
       Same configuration as in case of example in 3.1.1, but now in access checking function we are not using “generic rights mapping”. In this particular case the “integrity checking” would be again performed only comparising two “mandatory policy levels” – from token and from security descriptor. So, even if “'SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0” in security descriptor the token would not have any access.
   
     *  The 'null DACL' with low integrity level in token but with 'SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0' but without 'mapping' and 'mandatory policy flags = 0'
       Same configuration as in case of example 3.1.2, but now we set “mandatory policy flags” in token to 0. This will allo complitely bypass all “integrity check” michanism. As a result the token with “untrusted mandatory policy level” will have access to security descriptor with “secure process mandaroty policy level”.
   
   3.2 Administrative privileges on token with low level 
   
Certain administrative Windows privileges can be assigned to an access token only with at least a high integrity level. If the access token integrity level is less than high, then specific administrative privileges are not allowed and are removed from the access token (or just set to 0). The administrative privileges associated with a high integrity level are:
   SeCreateTokenPrivilege
   SeTcbPrivilege
   SeTakeOwnershipPrivilege
   SeLoadDriverPrivilege
   SeBackupPrivilege
   SeRestorePrivilege
   SeDebugPrivilege
   SeImpersonatePrivilege
   SeRelabelPrivilege
   SeDelegateSessionUserImpersonatePrivilege
   This example shows that even if we force system to make a token with all these privileges, but use a “mandatory policy level” low tha “high level” then final token would have all these privilegs, but in “disabled” state. And it is not possible to enable them, even if no errors on system functions while enabling. The end of example shows that it is do possible to set all these privileges to “enabled” state for token with “mandatory policy level >= high level”.
   
4. Conditional ACEs
   
   1. [MS-DTYP] 2.4.4.17.9 Example 1: Attributes in Simple Form
   The example shows using of “conditional expression” directly from [MS-DTYP] document. User can also uncomment source code for using binary representation of the “conditional expression” (exactly from [MS-DTYP]).
   2. [MS-DTYP] 2.4.4.17.9 Example 2: Prefixed Attribute Names and Multiple Terms
   The example shows using of “conditional expression” directly from [MS-DTYP] document. User can also uncomment source code for using binary representation of the “conditional expression” (exactly from [MS-DTYP]).
   3. [MS-DTYP] 2.4.4.17.9 Example 3: RHS Attribute Variables and SID-based Operators
   The example shows using of “conditional expression” directly from [MS-DTYP] document. User can also uncomment source code for using binary representation of the “conditional expression” (exactly from [MS-DTYP]).
   4. Multiple values in "user attribute"
   There is a posibility to use multiple values of the same type inside “token attributes” (“user attributes” and “device attributes”) . It is not possible for “resource attribute” (in security descriptor): if user would put multiple attributes there system would report error during access checking.
   5. Using SID in "resource attribute" (undocumented format)
   While for other attribute types there are descriptions how they converted to binary format, such description for SID type is missing. The example shows how user can use SID type in “resource attribute”.
   6. Using “octet string” (binary) in "resource attribute" (undocumented format)
   While for other attribute types there are descriptions how they converted to binary format, such description for “octet string” type is missing. The example shows how user can use “octet string” type in “resource attribute”.
   7. Using an attribute as a simple boolean value
   There is a posibility to use any attribute as a single boolean value. It is not clear from official documentation that it is possible. The example shows such case of attribute usage.
      
5. Object ACEs
   
   There is a posibility to perform access checking not only for a particular object itself, but for object and a tree of “property sets” and “properties”. It is all done via using OBJECT_TYPE_LIST data type. The example shows a case when there is “object tree” with 8 nodes with different “deny” and “allow” rules for each of them. At the end user can check which access would be provided to each node in the tree.
