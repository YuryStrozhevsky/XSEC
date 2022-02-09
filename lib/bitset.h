/*

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

*/

#pragma once
//********************************************************************************************
namespace XSEC
{
	//****************************************************************************************
	#pragma region Pre-defined meanings for different types
	//****************************************************************************************
	using byte_meaning_t = std::array<std::array<std::wstring, 2>, 8>;
	using word_meaning_t = std::array<std::array<std::wstring, 2>, 16>;
	using dword_meaning_t = std::array<std::array<std::wstring, 2>, 32>;

	template<size_t> struct is_32 {};
	template<> struct is_32<32> { using type = bool; };

	const byte_meaning_t ByteBitsMeaningEmpty = { {
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""}
	} };

	const byte_meaning_t ByteBitsMeaningAceFlags = { {
		{L"OBJECT_INHERIT_ACE", L"Noncontainer child objects inherit the ACE as an effective ACE. For child objects that are containers, the ACE is inherited as an inherit - only ACE unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set"},
		{L"CONTAINER_INHERIT_ACE", L"Child objects that are containers, such as directories, inherit the ACE as an effective ACE. The inherited ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set"},
		{L"NO_PROPAGATE_INHERIT_ACE", L"If the ACE is inherited by a child object, the system clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE flags in the inherited ACE. This prevents the ACE from being inherited by subsequent generations of objects"},
		{L"INHERIT_ONLY_ACE", L"Indicates an inherit-only ACE, which does not control access to the object to which it is attached. If this flag is not set, the ACE is an effective ACE that controls access to the object to which it is attached. Both effective and inherit-only ACEs can be inherited depending on the state of the other inheritance flags"},
		{L"INHERITED_ACE", L"Indicates that the ACE was inherited. The system sets this bit when it propagates an inherited ACE to a child object"},
		{L"CRITICAL_ACE_FLAG", L"These control whether the ACE is critical and cannot be removed. Used only with access allowed ACE types to indicate that the ACE is critical and cannot be removed"},
		{L"SUCCESSFUL_ACCESS_ACE_FLAG", L"Used with system-audit ACEs in a SACL to generate audit messages for successful access attempts. Used only with system audit and alarm ACE types to indicate that a message is generated for successful accesses"},
		{L"FAILED_ACCESS_ACE_FLAG", L"Used with system-audit ACEs in a system access control list (SACL) to generate audit messages for failed access attempts. Used only with system audit and alarm ACE types to indicate that a message is generated for failed accesses"}
	} };

	const word_meaning_t WordBitsMeaningEmpty = { {
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""}
	} };

	const word_meaning_t WordBitsMeaningSdControl = { {
		{L"SE_OWNER_DEFAULTED", L"Indicates that the SID pointed to by the Owner field was provided by a defaulting mechanism rather than explicitly provided by the original provider of the security descriptor"},
		{L"SE_GROUP_DEFAULTED", L"Indicates that the SID in the Group field was provided by a defaulting mechanism rather than explicitly provided by the original provider of the security descriptor"},
		{L"SE_DACL_PRESENT", L"Indicates that the security descriptor contains a discretionary ACL"},
		{L"SE_DACL_DEFAULTED", L"Indicates that the ACL pointed to by the Dacl field was provided by a defaulting mechanism rather than explicitly provided by the original provider of the security descriptor"},
		{L"SE_SACL_PRESENT", L"Indicates that the security descriptor contains a system ACL pointed to by the Sacl field"},
		{L"SE_SACL_DEFAULTED", L"Indicates that the ACL pointed to by the Sacl field was provided by a defaulting mechanism rather than explicitly provided by the original provider of the security descriptor"},
		{L"", L""},
		{L"", L""},
		{L"SE_DACL_AUTO_INHERIT_REQ", L"Set when the DACL is to be computed through inheritance. When both SE_DACL_AUTO_INHERIT_REQ and SE_DACL_AUTO_INHERITED are set, the resulting security descriptor sets SE_DACL_AUTO_INHERITED; the SE_DACL_AUTO_INHERIT_REQ setting is not preserved"},
		{L"SE_SACL_AUTO_INHERIT_REQ", L"Set when the SACL is to be computed through inheritance. When both SE_SACL_AUTO_INHERIT_REQ and SE_SACL_AUTO_INHERITED are set, the resulting security descriptor sets SE_SACL_AUTO_INHERITED; the SE_SACL_AUTO_INHERIT_REQ setting is not preserved"},
		{L"SE_DACL_AUTO_INHERITED", L"Set when the DACL was created through inheritance"},
		{L"SE_SACL_AUTO_INHERITED", L"Set when the SACL was created through inheritance"},
		{L"SE_DACL_PROTECTED", L"Set when the DACL will be protected from inherit operations"},
		{L"SE_SACL_PROTECTED", L"Set when the SACL will be protected from inherit operations"},
		{L"SE_RM_CONTROL_VALID", L"Set to 1 when the Sbz1 field is to be interpreted as resource manager control bits"},
		{L"SE_SELF_RELATIVE", L"Indicates that the security descriptor is in self-relative form"}
	} };

	const dword_meaning_t DwordMeaningEmpty = { {
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
	} };

	const dword_meaning_t DwordMeaningPrivilege = { {
		{L"SE_PRIVILEGE_ENABLED_BY_DEFAULT", L"The privilege is enabled by default"},
		{L"SE_PRIVILEGE_ENABLED", L"The privilege is enabled"},
		{L"SE_PRIVILEGE_REMOVED", L"Used to remove a privilege"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"SE_PRIVILEGE_USED_FOR_ACCESS", L"The privilege was used to gain access to an object or service. This flag is used to identify the relevant privileges in a set passed by a client application that may contain unnecessary privileges"},
	} };

	const dword_meaning_t DwordMeaningDefault = { {
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningToken = { {
		{L"TOKEN_ASSIGN_PRIMARY", L"Required to attach a primary token to a process. The SE_ASSIGNPRIMARYTOKEN_NAME privilege is also required to accomplish this task"},
		{L"TOKEN_DUPLICATE", L"Required to duplicate an access token"},
		{L"TOKEN_IMPERSONATE", L"Required to attach an impersonation access token to a process"},
		{L"TOKEN_QUERY", L"Required to query an access token"},
		{L"TOKEN_QUERY_SOURCE", L"Required to query the source of an access token"},
		{L"TOKEN_ADJUST_PRIVILEGES", L"Required to enable or disable the privileges in an access token"},
		{L"TOKEN_ADJUST_GROUPS", L"Required to adjust the attributes of the groups in an access token"},
		{L"TOKEN_ADJUST_DEFAULT", L"Required to change the default owner, primary group, or DACL of an access token"},
		{L"TOKEN_ADJUST_SESSIONID", L"Required to adjust the session ID of an access token. The SE_TCB_NAME privilege is required"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningFile = { {
		{L"FILE_READ_DATA", L"For a file object, the right to read the corresponding file data. For a directory object, the right to read the corresponding directory data"},
		{L"FILE_WRITE_DATA", L"For a file object, the right to write data to the file. For a directory object, the right to create a file in the directory"},
		{L"FILE_APPEND_DATA", L"For a file object, the right to append data to the file. (For local files, write operations will not overwrite existing data if this flag is specified without FILE_WRITE_DATA.) For a directory object, the right to create a subdirectory (FILE_ADD_SUBDIRECTORY)"},
		{L"FILE_READ_EA", L"The right to read extended file attributes"},
		{L"FILE_WRITE_EA", L"The right to write extended file attributes"},
		{L"FILE_EXECUTE", L"For a native code file, the right to execute the file. This access right given to scripts may cause the script to be executable, depending on the script interpreter"},
		{L"", L""},
		{L"FILE_READ_ATTRIBUTES", L"The right to read file attributes"},
		{L"FILE_WRITE_ATTRIBUTES", L"The right to write file attributes"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningDirectory = { {
		{L"FILE_LIST_DIRECTORY", L"For a directory, this value grants the right to list the contents of the directory"},
		{L"FILE_ADD_FILE", L"For a directory object, the right to create a file in the directory"},
		{L"FILE_ADD_SUBDIRECTORY", L"For a directory object, the right to create a subdirectory"},
		{L"FILE_READ_EA", L"The right to read extended file attributes"},
		{L"FILE_WRITE_EA", L"The right to write extended file attributes"},
		{L"FILE_TRAVERSE", L"For a directory, the directory can be traversed"},
		{L"FILE_DELETE_CHILD", L"Grants the right to delete a directory and all the files it contains (its children), even if the files are read-only"},
		{L"FILE_READ_ATTRIBUTES", L"The right to read file attributes"},
		{L"FILE_WRITE_ATTRIBUTES", L"The right to write file attributes"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningProcess = { {
		{L"PROCESS_TERMINATE", L"Required to terminate a process using TerminateProcess"},
		{L"PROCESS_CREATE_THREAD", L"Required to create a thread"},
		{L"PROCESS_SET_SESSIONID", L""},
		{L"PROCESS_VM_OPERATION", L"Required to perform an operation on the address space of a process (see VirtualProtectEx and WriteProcessMemory)"},
		{L"PROCESS_VM_READ", L"Required to read memory in a process using ReadProcessMemory"},
		{L"PROCESS_VM_WRITE", L"Required to write to memory in a process using WriteProcessMemory"},
		{L"PROCESS_DUP_HANDLE", L"Required to duplicate a handle using DuplicateHandle"},
		{L"PROCESS_CREATE_PROCESS", L"Required to create a process"},
		{L"PROCESS_SET_QUOTA", L"Required to set memory limits using SetProcessWorkingSetSize"},
		{L"PROCESS_SET_INFORMATION", L"Required to set certain information about a process, such as its priority class (see SetPriorityClass)"},
		{L"PROCESS_QUERY_INFORMATION", L"Required to retrieve certain information about a process, such as its token, exit code, and priority class (see OpenProcessToken)"},
		{L"PROCESS_SUSPEND_RESUME", L"Required to suspend or resume a process"},
		{L"PROCESS_QUERY_LIMITED_INFORMATION", L"Required to retrieve certain information about a process (see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName). A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION."},
		{L"PROCESS_SET_LIMITED_INFORMATION", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningPipe = { {
		{L"PIPE_ACCESS_INBOUND", L"FILE_GENERIC_READ and SYNCHRONIZE"},
		{L"PIPE_ACCESS_OUTBOUND", L"FILE_GENERIC_WRITE and SYNCHRONIZE"},
		{L"FILE_CREATE_PIPE_INSTANCE", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningThread = { {
		{L"THREAD_TERMINATE", L"Required to terminate a thread using TerminateThread"},
		{L"THREAD_SUSPEND_RESUME", L"(Works for resume befor Windows 8.1 only) Required to suspend or resume a thread (see SuspendThread and ResumeThread)"},
		{L"", L""},
		{L"THREAD_GET_CONTEXT", L"Required to read the context of a thread using GetThreadContext"},
		{L"THREAD_SET_CONTEXT", L"Required to write the context of a thread using SetThreadContext"},
		{L"THREAD_SET_INFORMATION", L"Required to set certain information in the thread object"},
		{L"THREAD_QUERY_INFORMATION", L"Required to read certain information from the thread object, such as the exit code (see GetExitCodeThread)"},
		{L"THREAD_SET_THREAD_TOKEN", L"Required to set the impersonation token for a thread using SetThreadToken"},
		{L"THREAD_IMPERSONATE", L"Required to use a thread's security information directly without calling it by using a communication mechanism that provides impersonation services"},
		{L"THREAD_DIRECT_IMPERSONATION", L"Required for a server thread that impersonates a client"},
		{L"THREAD_SET_LIMITED_INFORMATION", L"Required to set certain information in the thread object. A handle that has the THREAD_SET_INFORMATION access right is automatically granted THREAD_SET_LIMITED_INFORMATION"},
		{L"THREAD_QUERY_LIMITED_INFORMATION", L"Required to read certain information from the thread objects (see GetProcessIdOfThread). A handle that has the THREAD_QUERY_INFORMATION access right is automatically granted THREAD_QUERY_LIMITED_INFORMATION"},
		{L"THREAD_RESUME", L"(Windows 8.1+) Required to resume a thread (ResumeThread)"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningMemorySection = { {
		{L"SECTION_QUERY", L""},
		{L"SECTION_MAP_WRITE", L""},
		{L"SECTION_MAP_READ", L""},
		{L"SECTION_MAP_EXECUTE", L""},
		{L"SECTION_EXTEND_SIZE", L""},
		{L"SECTION_MAP_EXECUTE_EXPLICIT", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningFileMapping = { {
		{L"FILE_MAP_COPY", L"A copy-on-write view of the file is mapped"},
		{L"FILE_MAP_WRITE", L"Allows mapping of read-only, copy-on-write, or read/write views of a file-mapping object. The object must have been created with page protection that allows write access, such as PAGE_READWRITE or PAGE_EXECUTE_READWRITE protection"},
		{L"FILE_MAP_READ", L"Allows mapping of read-only or copy-on-write views of the file-mapping object"},
		{L"", L""},
		{L"", L""},
		{L"FILE_MAP_EXECUTE", L"Allows mapping of executable views of the file-mapping object. The object must have been created with page protection that allows execute access, such as PAGE_EXECUTE_READ, PAGE_EXECUTE_WRITECOPY, or PAGE_EXECUTE_READWRITE protection"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"FILE_MAP_LARGE_PAGES", L"Starting with Windows 10, version 1703, this flag specifies that the view should be mapped using large page support"},
		{L"FILE_MAP_TARGETS_INVALID", L"Sets all the locations in the mapped file as invalid targets for Control Flow Guard (CFG)"},
		{L"FILE_MAP_RESERVE", L""},
	} };

	const dword_meaning_t DwordMeaningWinStation = { {
		{L"WINSTA_ENUMDESKTOPS", L"Required to enumerate existing desktop objects"},
		{L"WINSTA_READATTRIBUTES", L"Required to read the attributes of a window station object. This attribute includes color settings and other global window station properties"},
		{L"WINSTA_ACCESSCLIPBOARD", L"Required to use the clipboard"},
		{L"WINSTA_CREATEDESKTOP", L"Required to create new desktop objects on the window station"},
		{L"WINSTA_WRITEATTRIBUTES", L"Required to modify the attributes of a window station object. The attributes include color settings and other global window station properties"},
		{L"WINSTA_ACCESSGLOBALATOMS", L"Required to manipulate global atoms"},
		{L"WINSTA_EXITWINDOWS", L"Required to successfully call the ExitWindows or ExitWindowsEx function. Window stations can be shared by users and this access type can prevent other users of a window station from logging off the window station owner"},
		{L"", L""},
		{L"WINSTA_ENUMERATE", L"Required for the window station to be enumerated"},
		{L"WINSTA_READSCREEN", L"Required to access screen contents"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningDesktop = { {
		{L"DESKTOP_READOBJECTS", L"Required to read objects on the desktop"},
		{L"DESKTOP_CREATEWINDOW", L"Required to create a window on the desktop"},
		{L"DESKTOP_CREATEMENU", L"Required to create a menu on the desktop"},
		{L"DESKTOP_HOOKCONTROL", L"Required to establish any of the window hooks"},
		{L"DESKTOP_JOURNALRECORD", L"Required to perform journal recording on a desktop"},
		{L"DESKTOP_JOURNALPLAYBACK", L"Required to perform journal playback on a desktop"},
		{L"DESKTOP_ENUMERATE", L"Required for the desktop to be enumerated"},
		{L"DESKTOP_WRITEOBJECTS", L"Required to write objects on the desktop"},
		{L"DESKTOP_SWITCHDESKTOP", L"Required to activate the desktop using the SwitchDesktop function"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningRegKey = { {
		{L"KEY_QUERY_VALUE", L"Required to query the values of a registry key"},
		{L"KEY_SET_VALUE", L"Required to create, delete, or set a registry value"},
		{L"KEY_CREATE_SUB_KEY", L"Required to create a subkey of a registry key"},
		{L"KEY_ENUMERATE_SUB_KEYS", L"Required to enumerate the subkeys of a registry key"},
		{L"KEY_NOTIFY", L"Required to request change notifications for a registry key or for subkeys of a registry key"},
		{L"KEY_CREATE_LINK", L"Reserved for system use"},
		{L"", L""},
		{L"", L""},
		{L"KEY_WOW64_64KEY", L"Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values."},
		{L"KEY_WOW64_32KEY", L"Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningServiceControlManager = { {
		{L"SC_MANAGER_CONNECT", L"Required to connect to the service control manager"},
		{L"SC_MANAGER_CREATE_SERVICE", L"Required to call the CreateService function to create a service object and add it to the database"},
		{L"SC_MANAGER_ENUMERATE_SERVICE", L"Required to call the EnumServicesStatus or EnumServicesStatusEx function to list the services that are in the database. Required to call the NotifyServiceStatusChange function to receive notification when any service is created or deleted"},
		{L"SC_MANAGER_LOCK", L"Required to call the LockServiceDatabase function to acquire a lock on the database"},
		{L"SC_MANAGER_QUERY_LOCK_STATUS", L"Required to call the QueryServiceLockStatus function to retrieve the lock status information for the database"},
		{L"SC_MANAGER_MODIFY_BOOT_CONFIG", L"Required to call the NotifyBootConfigStatus function"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningService = { {
		{L"SERVICE_QUERY_CONFIG", L"Required to call the QueryServiceConfig and QueryServiceConfig2 functions to query the service configuration"},
		{L"SERVICE_CHANGE_CONFIG", L"Required to call the ChangeServiceConfig or ChangeServiceConfig2 function to change the service configuration. Because this grants the caller the right to change the executable file that the system runs, it should be granted only to administrators"},
		{L"SERVICE_QUERY_STATUS", L"Required to call the QueryServiceStatus or QueryServiceStatusEx function to ask the service control manager about the status of the service. Required to call the NotifyServiceStatusChange function to receive notification when a service changes status"},
		{L"SERVICE_ENUMERATE_DEPENDENTS", L"Required to call the EnumDependentServices function to enumerate all the services dependent on the service"},
		{L"SERVICE_START", L"Required to call the StartService function to start the service"},
		{L"SERVICE_STOP", L"Required to call the ControlService function to stop the service"},
		{L"SERVICE_PAUSE_CONTINUE", L"Required to call the ControlService function to pause or continue the service"},
		{L"SERVICE_INTERROGATE", L"Required to call the ControlService function to ask the service to report its status immediately"},
		{L"SERVICE_USER_DEFINED_CONTROL", L"Required to call the ControlService function to specify a user-defined control code"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningEvent = { {
		{L"", L""},
		{L"EVENT_MODIFY_STATE", L"Modify state access, which is required for the SetEvent, ResetEvent and PulseEvent functions"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningMutex = { {
		{L"MUTEX_MODIFY_STATE", L"Reserved for future use"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningSemaphore = { {
		{L"", L""},
		{L"SEMAPHORE_MODIFY_STATE", L"Modify state access, which is required for the ReleaseSemaphore function"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningTimer = { {
		{L"TIMER_QUERY_STATE", L"Reserved for future use"},
		{L"TIMER_MODIFY_STATE", L"Modify state access, which is required for the SetWaitableTimer and CancelWaitableTimer functions"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningJob = { {
		{L"JOB_OBJECT_ASSIGN_PROCESS", L"Required to call the AssignProcessToJobObject function to assign processes to the job object"},
		{L"JOB_OBJECT_SET_ATTRIBUTES", L"Required to call the SetInformationJobObject function to set the attributes of the job object"},
		{L"JOB_OBJECT_QUERY", L"Required to retrieve certain information about a job object, such as attributes and accounting information (see QueryInformationJobObject and IsProcessInJob)"},
		{L"JOB_OBJECT_TERMINATE", L"Required to call the TerminateJobObject function to terminate all processes in the job object"},
		{L"JOB_OBJECT_SET_SECURITY_ATTRIBUTES", L"This flag is not supported. You must set security limitations individually for each process associated with a job object.Windows Server 2003 and Windows XP: Required to call the SetInformationJobObject function with the JobObjectSecurityLimitInformation information class to set security limitations for the processes associated with the job object. Support for this flag was removed in Windows Vista and Windows Server 2008"},
		{L"JOB_OBJECT_IMPERSONATE", L"?"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	// Every object in Active Directory has an nTSecurityDescriptor attribute whose value is the security
	// descriptor that contains access control information for the object
	const dword_meaning_t DwordMeaningActiveDirectoryObject = { {
		{L"RIGHT_DS_CREATE_CHILD", L"The right to create child objects of the object"},
		{L"RIGHT_DS_DELETE_CHILD", L"The right to delete child objects of the object"},
		{L"RIGHT_DS_LIST_CONTENTS", L"The right to list child objects of this object"},
		{L"RIGHT_DS_WRITE_PROPERTY_EXTENDED", L"The right to perform an operation controlled by a validated write access right"},
		{L"RIGHT_DS_READ_PROPERTY", L"The right to read properties of the object"},
		{L"RIGHT_DS_WRITE_PROPERTY", L"The right to write properties of the object"},
		{L"RIGHT_DS_DELETE_TREE", L"The right to perform a Delete-Tree operation on the object"},
		{L"RIGHT_DS_LIST_OBJECT", L"The right to list a particular object"},
		{L"RIGHT_DS_CONTROL_ACCESS", L"The right to perform an operation controlled by a control access right"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningMandatoryLabel = { {
		{L"SYSTEM_MANDATORY_LABEL_NO_WRITE_UP", L"A principal with a lower mandatory level than the object cannot write to the object"},
		{L"SYSTEM_MANDATORY_LABEL_NO_READ_UP", L"A principal with a lower mandatory level than the object cannot read the object"},
		{L"SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP", L"A principal with a lower mandatory level than the object cannot execute the object"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
	} };

	const dword_meaning_t DwordMeaningSystemAccessRights = { {
		{L"POLICY_MODE_INTERACTIVE", L"SeInteractiveLogonRight"},
		{L"POLICY_MODE_NETWORK", L"SeNetworkLogonRight"},
		{L"POLICY_MODE_BATCH", L"SeBatchLogonRight"},
		{L"", L""},
		{L"POLICY_MODE_SERVICE", L"SeServiceLogonRight"},
		{L"", L""},
		{L"POLICY_MODE_DENY_INTERACTIVE", L"SeDenyInteractiveLogonRight"},
		{L"POLICY_MODE_DENY_NETWORK", L"SeDenyNetworkLogonRight"},
		{L"POLICY_MODE_DENY_BATCH", L"SeDenyBatchLogonRight"},
		{L"POLICY_MODE_DENY_SERVICE", L"SeDenyServiceLogonRight"},
		{L"POLICY_MODE_REMOTE_INTERACTIVE", L"SeRemoteInteractiveLogonRight"},
		{L"POLICY_MODE_DENY_REMOTE_INTERACTIVE", L"SeDenyRemoteInteractiveLogonRight"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
	} };

	const dword_meaning_t DwordMeaningLSAAccount = { {
		{L"ACCOUNT_VIEW", L"This access type is required to read the account information. This includes the privileges assigned to the account, memory quotas assigned, and any special access types granted"},
		{L"ACCOUNT_ADJUST_PRIVILEGES", L"This access type is required to assign privileges to or remove privileges from an account"},
		{L"ACCOUNT_ADJUST_QUOTAS", L"This access type is required to change the system quotas assigned to an account"},
		{L"ACCOUNT_ADJUST_SYSTEM_ACCESS", L"This access type is required to update the system access flags for the account"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningLSAPolicy = { {
		{L"POLICY_VIEW_LOCAL_INFORMATION", L"This access type is needed to read the target system's miscellaneous security policy information. This includes the default quota, auditing, server state and role information, and trust information. This access type is also needed to enumerate trusted domains, accounts, and privileges"},
		{L"POLICY_VIEW_AUDIT_INFORMATION", L"This access type is needed to view audit trail or audit requirements information"},
		{L"POLICY_GET_PRIVATE_INFORMATION", L"This access type is needed to view sensitive information, such as the names of accounts established for trusted domain relationships"},
		{L"POLICY_TRUST_ADMIN", L"This access type is needed to change the account domain or primary domain information"},
		{L"POLICY_CREATE_ACCOUNT", L"This access type is needed to create a new Account object"},
		{L"POLICY_CREATE_SECRET", L"This access type is needed to create a new Private Data object"},
		{L"POLICY_CREATE_PRIVILEGE", L"Not yet supported"},
		{L"POLICY_SET_DEFAULT_QUOTA_LIMITS", L"Set the default system quotas that are applied to user accounts (Quota limits are not currently a part of the protocol, so this flag is not actively used)"},
		{L"POLICY_SET_AUDIT_REQUIREMENTS", L"This access type is needed to update the auditing requirements of the system"},
		{L"POLICY_AUDIT_LOG_ADMIN", L"This access type is needed to change the characteristics of the audit trail such as its maximum size or the retention period for audit records, or to clear the log"},
		{L"POLICY_SERVER_ADMIN", L"This access type is needed to modify the server state or role (master/replica) information. It is also needed to change the replica source and account name information"},
		{L"POLICY_LOOKUP_NAMES", L"This access type is needed to translate between names and SIDs"},
		{L"POLICY_NOTIFICATION", L"Access to be notified of policy changes"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningLSASecret = { {
		{L"SECRET_SET_VALUE", L"Set secret value."},
		{L"SECRET_QUERY_VALUE", L"Query secret value."},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	const dword_meaning_t DwordMeaningLSATrustedDomain = { {
		{L"TRUSTED_QUERY_DOMAIN_NAME", L"View domain name information"},
		{L"TRUSTED_QUERY_CONTROLLERS", L"View 'Domain Controllers' information"},
		{L"TRUSTED_SET_CONTROLLERS", L"Change 'Domain Controllers' information"},
		{L"TRUSTED_QUERY_POSIX", L"View POSIX information"},
		{L"TRUSTED_SET_POSIX", L"Change POSIX information"},
		{L"TRUSTED_SET_AUTH", L"Change authentication information"},
		{L"TRUSTED_QUERY_AUTH", L"View authentication information"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"DELETE", L"Specifies access to delete an object"},
		{L"READ_CONTROL", L"Specifies access to read the security descriptor of an object"},
		{L"WRITE_DACL", L""},
		{L"WRITE_OWNER", L""},
		{L"SYNCHRONIZE", L"Specifies access to the object sufficient to synchronize or wait on the object"},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"ACCESS_SYSTEM_SECURITY", L"When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL"},
		{L"MAXIMUM_ALLOWED", L""},
		{L"RESERVED", L""},
		{L"RESERVED", L""},
		{L"GENERIC_ALL", L""},
		{L"GENERIC_EXECUTE", L""},
		{L"GENERIC_WRITE", L""},
		{L"GENERIC_READ", L""},
	} };

	//
	// LsaGetSystemAccessAccount
	//
	//// Security System Access Flags.  These correspond to the enumerated
	//// type values in SECURITY_LOGON_TYPE.
	////
	//// IF YOU ADD A NEW LOGON TYPE HERE, ALSO ADD IT TO THE POLICY_MODE_xxx
	//// data definitions.
	////

	//#define SECURITY_ACCESS_INTERACTIVE_LOGON             ((ULONG) 0x00000001L)
	//#define SECURITY_ACCESS_NETWORK_LOGON                 ((ULONG) 0x00000002L)
	//#define SECURITY_ACCESS_BATCH_LOGON                   ((ULONG) 0x00000004L)
	//#define SECURITY_ACCESS_SERVICE_LOGON                 ((ULONG) 0x00000010L)
	//#define SECURITY_ACCESS_PROXY_LOGON                   ((ULONG) 0x00000020L)
	//#define SECURITY_ACCESS_DENY_INTERACTIVE_LOGON        ((ULONG) 0x00000040L)
	//#define SECURITY_ACCESS_DENY_NETWORK_LOGON            ((ULONG) 0x00000080L)
	//#define SECURITY_ACCESS_DENY_BATCH_LOGON              ((ULONG) 0x00000100L)
	//#define SECURITY_ACCESS_DENY_SERVICE_LOGON            ((ULONG) 0x00000200L)
	//#define SECURITY_ACCESS_REMOTE_INTERACTIVE_LOGON      ((ULONG) 0x00000400L)
	//#define SECURITY_ACCESS_DENY_REMOTE_INTERACTIVE_LOGON ((ULONG) 0x00000800L)

	const dword_meaning_t DwordMeaningAceType2Flags = { {
		{L"ACE_OBJECT_TYPE_PRESENT", L"ObjectType is present and contains a GUID. If this value is not specified, the InheritedObjectType member follows immediately after the Flags member."},
		{L"ACE_INHERITED_OBJECT_TYPE_PRESENT", L"InheritedObjectType is present and contains a GUID. If this value is not specified, all types of child objects can inherit the ACE."},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
	} };

	const dword_meaning_t DwordMeaningMandatoryPolicy = { {
		{L"TOKEN_MANDATORY_POLICY_NO_WRITE_UP", L"A process associated with the token cannot write to objects that have a greater mandatory integrity level"},
		{L"TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN", L"A process created with the token has an integrity level that is the lesser of the parent-process integrity level and the executable-file integrity level"},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
	} };

	const dword_meaning_t SidAndAttributesMeaningDefault = { {
		{ L"SE_GROUP_MANDATORY", L"The SID cannot have the SE_GROUP_ENABLED attribute cleared by a call to the AdjustTokenGroups function. However, you can use the CreateRestrictedToken function to convert a mandatory SID to a deny-only SID" },
		{ L"SE_GROUP_ENABLED_BY_DEFAULT", L"The SID is enabled by default" },
		{ L"SE_GROUP_ENABLED", L"The SID is enabled for access checks" },
		{ L"SE_GROUP_OWNER", L"The SID identifies a group account for which the user of the token is the owner of the group, or the SID can be assigned as the owner of the token or objects" },
		{ L"SE_GROUP_USE_FOR_DENY_ONLY", L"The SID is a deny-only SID in a restricted token" },
		{ L"SE_GROUP_INTEGRITY", L"The SID is a mandatory integrity SID" },
		{ L"SE_GROUP_INTEGRITY_ENABLED", L"The SID is enabled for mandatory integrity checks" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"SE_GROUP_RESOURCE", L"The SID identifies a domain-local group" },
		{ L"SE_GROUP_LOGON_ID (bit 1)", L"The SID is a logon SID that identifies the logon session associated with an access token. Consists of two bits (0xC value)"},
		{ L"SE_GROUP_LOGON_ID (bit 2)", L"The SID is a logon SID that identifies the logon session associated with an access token. Consists of two bits (0xC value)" }
	} };

	const dword_meaning_t SecurityAttributeV1Meaning = { {
		{ L"CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE", L"Attribute must not be inherited across process spawns" },
		{ L"CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE", L"Attribute value is compared in a case sensitive way. It is valid with string value or composite type containing string value" },
		{ L"CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY", L"Attribute is considered only for Deny access" },
		{ L"CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT", L"Attribute is disabled by default" },
		{ L"CLAIM_SECURITY_ATTRIBUTE_DISABLED", L"Attribute is disabled" },
		{ L"CLAIM_SECURITY_ATTRIBUTE_MANDATORY", L"Attribute is mandatory" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"FCI_CLAIM_SECURITY_ATTRIBUTE_MANUAL", L"The CLAIM_SECURITY_ATTRIBUTE has been manually assigned" },
		{ L"FCI_CLAIM_SECURITY_ATTRIBUTE_POLICY_DERIVED", L"The CLAIM_SECURITY_ATTRIBUTE has been determined by a central policy" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" },
		{ L"", L"" }
	} };

	const dword_meaning_t DwordMeaningAuditRights = { {
		{L"AUDIT_SET_SYSTEM_POLICY", L""},
		{L"AUDIT_QUERY_SYSTEM_POLICY", L""},
		{L"AUDIT_SET_USER_POLICY", L""},
		{L"AUDIT_QUERY_USER_POLICY", L""},
		{L"AUDIT_ENUMERATE_USERS", L""},
		{L"AUDIT_SET_MISC_POLICY", L""},
		{L"AUDIT_QUERY_MISC_POLICY", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
		{L"", L""},
	} };
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Common functions for bitset processing
	//****************************************************************************************
	template<size_t S>
	std::bitset<S> set_vec(const bin_t& data)
	{
		std::bitset<S> result;

		const size_t expected_data_size = (result.size() >> 3);
		const size_t valid_data_size = (data.size() < expected_data_size) ? data.size() : expected_data_size;

		for(size_t i = 0; i < valid_data_size; i++)
		{
			unsigned char element = data[i];

			for(unsigned char j = 0; j < 8; j++)
			{
				result[(i << 3) + j] = element & 1;
				element >>= 1;
			}
		}

		return result;
	}
	//****************************************************************************************
	template<size_t S>
	bin_t vec_set(const std::bitset<S>& data)
	{
		#pragma region Initial variables
		bin_t result;
		unsigned char element = 0;
		size_t k = 1;
		#pragma endregion

		#pragma region Additional check
		if(data.size() == 0)
			return bin_t();
		#pragma endregion

		#pragma region Special case for first bit
		if(data[0])
			element |= 1;
		#pragma endregion

		#pragma region main loop
		for(size_t i = 1; i < data.size();)
		{
			if(data[i])
				element |= (1 << k);

			i++;
			k++;

			if((i % 8) == 0)
			{
				result.push_back(element);
				element = 0;
				k = 0;
			}
		}
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Major XBITSET class
	//****************************************************************************************
	template<size_t S>
	struct XBITSET
	{
		XBITSET() = delete;
		~XBITSET() = default;

		XBITSET(const std::array<std::array<std::wstring, 2>, S>&, const std::vector<std::wstring>&);

		XBITSET(const std::bitset<S>&, const std::array<std::array<std::wstring, 2>, S>&);
		XBITSET(const char*, const std::array<std::array<std::wstring, 2>, S>&);

		XBITSET(const unsigned char data, const std::array<std::array<std::wstring, 2>, 8>& meaning = ByteBitsMeaningEmpty) : XBITSET<8>((unsigned char*)&data, meaning) {}
		XBITSET(const WORD data, const std::array<std::array<std::wstring, 2>, 16>& meaning = WordBitsMeaningEmpty) : XBITSET<16>((unsigned char*)&data, meaning) {}
		XBITSET(const DWORD data, const std::array<std::array<std::wstring, 2>, 32>& meaning = DwordMeaningEmpty) : XBITSET<32>((unsigned char*)&data, meaning) {}

		// Could be useful when user do not really bother about value
		XBITSET(const int data, const std::array<std::array<std::wstring, 2>, 32>& meaning = DwordMeaningEmpty) : XBITSET<32>((unsigned char*)&data, meaning) {}

		XBITSET(const unsigned char*, const std::array<std::array<std::wstring, 2>, S>&);
		XBITSET(const bin_t&, const std::array<std::array<std::wstring, 2>, S>&);
		XBITSET(const msxml_et&, const std::array<std::array<std::wstring, 2>, S>&);

		explicit operator char*() const;
		explicit operator bin_t() const;
		explicit operator xml_t() const;

		explicit operator DWORD() const;
		explicit operator WORD() const;
		explicit operator BYTE() const;

		bool get(DWORD);

		bool get(size_t);
		bool get(std::wstring);

		bool set(DWORD, bool);

		bool set(size_t, bool);
		bool set(std::wstring, bool);
		bool set(const std::vector<std::wstring>&, bool);

		std::bitset<S> Bits;
		const std::array<std::array<std::wstring, 2>, S> Meaning;

		const size_t Length = (S >> 3);
	};
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::XBITSET(const std::array<std::array<std::wstring, 2>, S>& meaning, const std::vector<std::wstring>& meanings) : Meaning(meaning)
	{
		if(false == set(meanings, true))
			throw std::exception("XBITSET: incorrect 'Meanings' array");
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::XBITSET(const std::bitset<S>& bits, const std::array<std::array<std::wstring, 2>, S>& meaning) : Bits(bits), Meaning(meaning)
	{
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::XBITSET(const char* string, const std::array<std::array<std::wstring, 2>, S>& meaning) : Bits(string), Meaning(meaning)
	{
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::XBITSET(const unsigned char* data, const std::array<std::array<std::wstring, 2>, S>& meaning) : Meaning(meaning)
	{
		#pragma region Initial check
		if(nullptr == data)
			throw std::exception("XBITSET: invalid input data");
		#pragma endregion

		#pragma region Main loop
		for(size_t i = 0; i < Length; i++)
		{
			unsigned char element = data[i];

			for(unsigned char j = 0; j < 8; j++)
			{
				Bits[(i << 3) + j] = element & 1;
				element >>= 1;
			}
		}
		#pragma endregion
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::XBITSET(const bin_t& data, const std::array<std::array<std::wstring, 2>, S>& meaning) : Meaning(meaning), Bits(set_vec<S>(data))
	{
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::XBITSET(const msxml_et& xml, const std::array<std::array<std::wstring, 2>, S>& meaning) : Meaning(meaning)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XBITSET: NULL as input XML");
		#pragma endregion

		#pragma region Read all data
		#pragma region Bits
		msxml_et xmlbits = xml->selectSingleNode(L"Bits");
		if(nullptr != xmlbits)
		{
			for(size_t i = 0; i < Bits.size(); i++)
			{
				_bstr_t bit_name = _bstr_t(L"b") + ((i < 10) ? _bstr_t(L"0") : _bstr_t()) + _variant_t(i).operator _bstr_t();

				msxml_et bit = xmlbits->selectSingleNode(bit_name);
				if(nullptr == bit)
					throw std::exception("XBITSET: not all bits are in input XML");

				Bits[i] = ((bit->text.operator==(L"0")) ? false : true);
			}
		}
		else
		{
			#pragma region Data
			msxml_et data = xml->selectSingleNode(L"Data");
			if(nullptr == data)
				throw std::exception("XBITSET: no 'Bits' and 'Data' in input XML");

			Bits = set_vec<S>(from_hex_codes((wchar_t*)data->text));
			#pragma endregion
		}
		#pragma endregion
		#pragma endregion
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::operator char*() const
	{
		return Bits.to_string();
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::operator bin_t() const
	{
		return vec_set(Bits);
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::operator xml_t() const
	{
		return [&](msxml_dt xml, std::optional<const wchar_t*> root) -> msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("BIISET: invalid output XML");
			#pragma endregion

			#pragma region Root element
			msxml_et byteBits = xml->createElement(std::wstring(root.value_or(L"XBITSET")).c_str());
			if(nullptr == byteBits)
				throw std::exception("XBITSET: cannot create root XML element");
			#pragma endregion

			#pragma region Append all data
			#pragma region Data
			msxml_et data = xml->createElement(L"Data");
			if(nullptr == data)
				throw std::exception("XBITSET: cannot create 'Data' XML element");

			data->appendChild(xml->createTextNode(whex_codes(vec_set(Bits)).c_str()));

			byteBits->appendChild(data);
			#pragma endregion

			#pragma region Bits
			msxml_et xmlbits = xml->createElement(L"Bits");
			if(nullptr == xmlbits)
				throw std::exception("XBITSET: cannot create 'Bits' XML element");

			for(size_t i = 0; i < Bits.size(); i++)
			{
				_bstr_t bit_name = _bstr_t(L"b") + ((i < 10) ? _bstr_t(L"0") : _bstr_t()) + _variant_t(i).operator _bstr_t();

				msxml_et bit = xml->createElement(bit_name);
				if(nullptr == bit)
					throw std::exception("XBITSET: cannot create one of 'Bits' XML element");

				std::array<std::wstring, 2> element = Meaning.at(i);
				std::wstring meaning = element.at(0);
				if(meaning.empty() == false)
				{
					msxml_at xmlMeaning = xml->createAttribute(L"Meaning");
					if(nullptr == xmlMeaning)
						throw std::exception("XBITSET: cannot create 'Meaning' XML attribute");

					xmlMeaning->value = meaning.c_str();
					bit->setAttributeNode(xmlMeaning);
				}

				bit->appendChild(xml->createTextNode(Bits[i] ? L"1" : L"0"));

				xmlbits->appendChild(bit);
			}

			byteBits->appendChild(xmlbits);
			#pragma endregion
			#pragma endregion

			return byteBits;
		};
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::operator DWORD()const
	{
		throw std::exception("XBITSET: can cast to DWORD for XBITSET<32> only");
	}
	//****************************************************************************************
	template<>
	XBITSET<32>::operator DWORD()const
	{
		return dword_vec(vec_set(Bits));
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::operator WORD()const
	{
		throw std::exception("XBITSET: can cast to WORD for XBITSET<16> only");
	}
	//****************************************************************************************
	template<>
	XBITSET<16>::operator WORD()const
	{
		return word_vec(vec_set(Bits));
	}
	//****************************************************************************************
	template<size_t S>
	XBITSET<S>::operator BYTE()const
	{
		throw std::exception("XBITSET: can cast to BYTE for XBITSET<8> only");
	}
	//****************************************************************************************
	template<>
	XBITSET<8>::operator BYTE()const
	{
		return byte_vec(vec_set(Bits));
	}
	//****************************************************************************************
	template<size_t S>
	bool XBITSET<S>::get(std::wstring value)
	{
		for(size_t i = 0; i < Meaning.size(); i++)
		{
			if(Meaning[i][0] == value)
				return (Bits[i] == 1);
		}

		throw std::exception("XBITSET: cannot find a correct 'meaning string'");
	}
	//****************************************************************************************
	template<size_t S>
	bool XBITSET<S>::get(DWORD)
	{
		throw std::exception("XBITSET: 'get(DWORD)' exists for XBITSET<32> only");
	}
	//****************************************************************************************
	template<>
	bool XBITSET<32>::get(DWORD value)
	{
		auto vec = vec_set(Bits);

		DWORD result = 0;

		for(size_t i = 0; i < vec.size(); i++)
		{
			((BYTE*)&result)[i] = vec[i];
			if(i == 4)
				break;
		}

		return ((result & value) == value);
	}
	//****************************************************************************************
	template<size_t S>
	bool XBITSET<S>::get(size_t value)
	{
		return Bits[value];
	}
	//****************************************************************************************
	template<size_t S>
	bool XBITSET<S>::set(size_t index, bool value)
	{
		if(Bits.size() < (index + 1))
			return false;

		Bits[index] = (value) ? 1 : 0;
		return true;
	}
	//****************************************************************************************
	template<size_t S>
	bool XBITSET<S>::set(std::wstring meaning, bool value)
	{
		for(size_t i = 0; i < Meaning.size(); i++)
		{
			if(Meaning[i][0] == meaning)
			{
				Bits[i] = (value) ? 1 : 0;
				return true;
			}
		}

		return false;
	}
	//****************************************************************************************
	template<size_t S>
	bool XBITSET<S>::set(const std::vector<std::wstring>& meanings, bool value)
	{
		if(!meanings.size())
			return false;

		for(auto&& element : meanings)
		{
			bool found = false;

			for(size_t i = 0; i < Meaning.size(); i++)
			{
				if(Meaning[i][0] == element)
				{
					Bits[i] = (value) ? 1 : 0;
					found = true;
					break;
				}
			}

			if(false == found)
				return false;
		}

		return true;
	}
	//****************************************************************************************
	template<size_t S>
	bool XBITSET<S>::set(DWORD, bool)
	{
		throw std::exception("XBITSET: 'set(DWORD)' exists for XBITSET<32> only");
	}
	//****************************************************************************************
	template<>
	bool XBITSET<32>::set(DWORD mask, bool value)
	{
		auto vec = vec_set(Bits);

		DWORD result = 0;

		((BYTE*)&result)[0] = vec[0];
		((BYTE*)&result)[1] = vec[1];
		((BYTE*)&result)[2] = vec[2];
		((BYTE*)&result)[3] = vec[3];

		if(value)
			result |= mask;
		else
			result &= ~mask;

		vec[0] = ((BYTE*)&result)[0];
		vec[1] = ((BYTE*)&result)[1];
		vec[2] = ((BYTE*)&result)[2];
		vec[3] = ((BYTE*)&result)[3];

		Bits = set_vec<32>(vec);

		return true;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
};
//********************************************************************************************

