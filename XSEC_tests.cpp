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

#include "pch.h"
#include "CppUnitTest.h"

#include "./lib/index.h"

#include <tuple>
#include <filesystem>
#include <fstream>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace XSEC;

//********************************************************************************
std::tuple<BOOL, std::vector<DWORD>, std::vector<DWORD>, std::vector<std::string>> check_access(
	const std::wstring name,
	const HANDLE& token,
	const XSEC::XSD& sd,
	DWORD desired_access,
	bool zero_mapping = false,
	std::optional<std::vector<OBJECT_TYPE_LIST>> object_type_list = std::nullopt,
	std::optional<XSEC::XSID> self = std::nullopt
)
{
	#pragma region Initial variables
	BOOL check_result = FALSE;

	PRIVILEGE_SET privileges = { 0 };
	DWORD privileges_length = sizeof(privileges);

	BOOL GenerateOnClose = FALSE;

	GENERIC_MAPPING mapping;
	#pragma endregion

	#pragma region Set a correct "mapping" values
	if (zero_mapping)
		mapping = { 0x00 };
	else
	{
		mapping = { 0xFFFFFFFF };
		mapping.GenericRead = FILE_GENERIC_READ;
		mapping.GenericWrite = FILE_GENERIC_WRITE;
		mapping.GenericExecute = FILE_GENERIC_EXECUTE;
		mapping.GenericAll = FILE_ALL_ACCESS;
	}
	#pragma endregion

	#pragma region Initialize values related to "object list"
	std::vector<OBJECT_TYPE_LIST> object_list_value = object_type_list.value_or(std::vector<OBJECT_TYPE_LIST>{});

	GUID zero = { 0x00000000, 0x0000, 0x0000, { 0x00, 0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00 } };

	if (object_list_value.size() == 0)
	{
		// The object list must have at least one element 
		// identifying the root object itself
		object_list_value.push_back({
			0,
			0,
			&zero
			});
	}
	#pragma endregion

	#pragma region Initialize "result values"
	size_t size = object_list_value.size();

	std::vector<DWORD> granted_access(size, 0);
	std::vector<DWORD> access_status(size, 0);
	#pragma endregion

	#pragma region Initialize correct "PrincipalSelf" substitute value
	XSEC::bin_t bin_self;
	PSID sid_self = NULL;
	if (self)
	{
		bin_self = (XSEC::bin_t)self.value();
		sid_self = bin_self.data();
	}
	#pragma endregion

	#pragma region Convert security descriptor into binary format
	auto bin = (XSEC::bin_t)sd;
	#pragma endregion

	#pragma region Make an impersonation token from primary
	HANDLE dup_token;
	if (FALSE == DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityDelegation, TokenImpersonation, &dup_token))
		throw std::exception("AccessCheck: cannot duplicate token");
	#pragma endregion

	#pragma region Check access
	check_result = AccessCheckByTypeResultListAndAuditAlarmByHandle(
		L"XSEC Tests",
		nullptr,
		dup_token,
		L"Test security descriptor",
		name.c_str(),
		(PSECURITY_DESCRIPTOR)bin.data(),
		sid_self,
		desired_access,
		AuditEventObjectAccess,
		AUDIT_ALLOW_NO_PRIVILEGE,
		object_list_value.data(),
		object_list_value.size(),
		&mapping,
		FALSE,
		granted_access.data(),
		access_status.data(),
		&GenerateOnClose
	);
	if (FALSE == check_result)
	{
		std::stringstream stream;
		stream << "AccessCheck: error during a check, #" << GetLastError() << "\n";

		throw std::exception(stream.str().c_str());
	}
	#pragma endregion

	std::vector<std::string> granted_access_string;
	std::transform(granted_access.begin(), granted_access.end(), std::back_inserter(granted_access_string), [](DWORD value) -> std::string { return std::bitset<32>(value).to_string();	});

	return std::make_tuple(check_result, granted_access, access_status, granted_access_string);
}
//********************************************************************************
namespace XSECTests
{
	TEST_CLASS(XSECTests)
	{
	public:

		#pragma region Common variables
		XSID fiction_owner{ L"S-1-5-21-3522493417-3251241581-1305895453-513" }; // Fiction owner (in order to exclude additional "common access rights" in case owner are equal with token's owner)
		XSID fiction_group{ L"S-1-5-21-3522493417-3251241581-1305895453-514" };
		#pragma endregion

		TEST_CLASS_INITIALIZE(SetupMethod)
		{
			CoInitialize(NULL);

			HANDLE token;

			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
				throw std::exception("XSEC Test: cannot get process token");

			// In order to have audit message generation function working we need to set "SeAuditPrivilege"
			// in the PROCESS token, NOT in a thread token. So, even if the access check would be
			// against a context from thread token the "SeAuditPrivilege" MUST be set in PROCESS token.
			if (FALSE == XTOKEN::ChangePrivileges({ L"SeAuditPrivilege" }, token))
				throw std::exception("XSEC Test: cannot set necessary privileges");

			CloseHandle(token);
		}

		TEST_CLASS_CLEANUP(ClearMethod)
		{
			CoUninitialize();
		}

		TEST_METHOD(BASIC)
		{
			auto token = XTOKEN::Create(XSID::CurrentUser);

			#pragma region The "null DACL"
			// If a security descriptor has no DACL at all (null DACL) then all SIDs allowed
			auto [result1, granted_access1, access_status1, granted_access_string1] = check_access(
				L"The 'null DACL'",
				token,
				{ fiction_owner },
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access1[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion

			#pragma region Empty DACL
			// If a security descriptor has an "empty DACL" (DACL exists, but has no ACEs) then no SIDs allowed
			auto [result2, granted_access2, access_status2, granted_access_string2] = check_access(
				L"Empty DACL",
				token,
				{ fiction_owner, { std::initializer_list<XACE>{} } },
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access2[0], (DWORD)0);

			// When we set "SeTakeOwnershipPrivilege" in token we can get WRITE_OWNER access even to this "unaccesable" SD
			auto [result2_1, granted_access2_1, access_status2_1, granted_access_string2_1] = check_access(
				L"Empty DACL but with SeTakeOwnershipPrivilege",
				XTOKEN::Create(
					XSID::CurrentUser,
					XSID::Everyone,
					{ { L"SeTakeOwnershipPrivilege" } }
				),
				{ fiction_owner, { std::initializer_list<XACE>{} } },
				WRITE_OWNER
			);

			Assert::AreEqual(granted_access2_1[0], (DWORD)WRITE_OWNER);

			// For an owner in SD there are always "READ_CONTROL + WRITE_DAC" access.
			// So, even if here we have "empty DACL" owner can get "READ_CONTROL + WRITE_DAC" access rights.
			auto [result2_2, granted_access2_2, access_status2_2, granted_access_string2_2] = check_access(
				L"Empty DACL but with special access rights for SD owner",
				XTOKEN::Create(
					fiction_owner
				),
				{ fiction_owner, { std::initializer_list<XACE>{} } },
				READ_CONTROL | WRITE_DAC
			);

			Assert::AreEqual(granted_access2_2[0], (DWORD)(READ_CONTROL | WRITE_DAC));
			#pragma endregion

			#pragma region Common denied ACE
			// In a "common case" denied ACEs must be before "allowed" ACEs and should have non-zero access mask
			auto [result3, granted_access3, access_status3, granted_access_string3] = check_access(
				L"Common denied ACE",
				XTOKEN::Create(
					XSID::CurrentUser,
					fiction_group
				),
				{
					fiction_owner,
					{{
						XACCESS_DENIED_ACE(
							XSID::CurrentUser,
							(DWORD)FILE_READ_ACCESS
						),
				// The "Everyone" group cannot be using as a "all users in the world" always.
				// If the "Everyone" group would not exist in token's SIDs then
				// "Everyone" would not be considered during access checking.
				XACCESS_ALLOWED_ACE(
					XSID::Everyone,
					(DWORD)(FILE_READ_ACCESS | FILE_WRITE_ACCESS)
				),
				XACCESS_ALLOWED_ACE(
					fiction_group,
					(DWORD)(FILE_READ_ACCESS | FILE_WRITE_ACCESS | FILE_APPEND_DATA)
				)
			}}
				},
				FILE_READ_ACCESS | FILE_WRITE_ACCESS | FILE_APPEND_DATA
			);

			// In fact access for this particular token to this particular SD was denied.
			// It is because "desired access = FILE_READ_ACCESS | FILE_WRITE_ACCESS | FILE_APPEND_DATA",
			// but for user's SID some access was denied (FILE_READ_ACCESS). So, even if "granted access" has a value
			// in general access was denied (not all access from "desired access" was satisfied).
			Assert::AreEqual(granted_access3[0], (DWORD)(FILE_WRITE_ACCESS | FILE_APPEND_DATA));
			#pragma endregion

			#pragma region Denied ACE after allowed
			// In case of a wrong ACE order the system access checking function would allow
			// all access because the the function meet allow rule first
			auto [result4, granted_access4, access_status4, granted_access_string4] = check_access(
				L"Denied ACE after allowed",
				token,
				{
					fiction_owner,
					{{
						XACCESS_ALLOWED_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS
						),
						XACCESS_DENIED_ACE(
							XSID::CurrentUser,
							(DWORD)FILE_READ_ACCESS
						)
					}}
				},
				FILE_READ_ACCESS | FILE_WRITE_ACCESS
			);

			Assert::AreEqual(granted_access4[0], (DWORD)FILE_READ_ACCESS | FILE_WRITE_ACCESS);
			#pragma endregion

			#pragma region Denied ACE with zero access mask
			// In case of a correct ACE order but when denied ACE has zero access mask system access
			// cheching function do not count the denied ACE (the denied ACE deny nothing)
			auto [result5, granted_access5, access_status5, granted_access_string5] = check_access(
				L"Denied ACE with zero access mask",
				token,
				{
					fiction_owner,
					{{
						XACCESS_DENIED_ACE(
							XSID::CurrentUser,
							(DWORD)0
						),
						XACCESS_ALLOWED_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS
						)
					}}
				},
				FILE_READ_ACCESS | FILE_WRITE_ACCESS
			);

			Assert::AreEqual(granted_access5[0], (DWORD)FILE_READ_ACCESS | FILE_WRITE_ACCESS);
			#pragma endregion

			#pragma region Denied access for group
			// In this case there is a "deny rule" for group in token. But the group do not have "SE_GROUP_ENABLED" flag set.
			// That is why access checking would not consider the "deny rule" and will grant full access to the SD.
			auto [result6, granted_access6, access_status6, granted_access_string6] = check_access(
				L"Denied access for group",
				XTOKEN::Create(
					XSID::CurrentUser,
					XSID::Everyone,
					{},
					{ { fiction_group, (DWORD)0 } }
				),
				{
					fiction_owner,
					{{
						XACCESS_DENIED_ACE(
							fiction_group,
							(DWORD)FILE_ALL_ACCESS
						),
						XACCESS_ALLOWED_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS
						)
					}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access6[0], (DWORD)FILE_ALL_ACCESS);

			// In order to not allow any user to disable critical groups the group in token must have at least "SE_GROUP_MANDATORY" flag set
			auto [result6_1, granted_access6_1, access_status6_1, granted_access_string6_1] = check_access(
				L"Denied access for group but with SE_GROUP_MANDATORY flag set",
				XTOKEN::Create(
					XSID::CurrentUser,
					XSID::Everyone,
					{},
					{ { fiction_group, { SidAndAttributesMeaningDefault, { L"SE_GROUP_MANDATORY" } } } }
				),
				{
					fiction_owner,
					{{
						XACCESS_DENIED_ACE(
							fiction_group,
							(DWORD)FILE_ALL_ACCESS
						),
						XACCESS_ALLOWED_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS
						)
					}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access6_1[0], (DWORD)0);
			#pragma endregion

			#pragma region Inheritence in ACE
			auto [result7, granted_access7, access_status7, granted_access_string7] = check_access(
				L"Inheritence in ACE",
				XTOKEN::Create(
					XSID::CurrentUser,
					XSID::Everyone,
					{},
					{ { fiction_group, { SidAndAttributesMeaningDefault, { L"SE_GROUP_MANDATORY" } } } }
				),
				{
					fiction_owner,
					{{
							// This ACE would not count because it has "INHERIT_ONLY_ACE" flag set
							XACCESS_DENIED_ACE(
								fiction_group,
								(DWORD)FILE_ALL_ACCESS,
								{ ByteBitsMeaningAceFlags, { L"INHERIT_ONLY_ACE" } }
							),
							XACCESS_ALLOWED_ACE(
								XSID::Everyone,
								(DWORD)FILE_ALL_ACCESS,
								{
									ByteBitsMeaningAceFlags,
									{
										L"INHERITED_ACE", // Simple flag representing the ACE was inhirited 
										L"OBJECT_INHERIT_ACE", // It will be applicable to all descendant files
										L"CONTAINER_INHERIT_ACE", // It will be applicable to all descendant folders
										L"NO_PROPAGATE_INHERIT_ACE" // If the ACE is inherited by a child object, the system clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE flags in the inherited ACE. This prevents the ACE from being inherited by subsequent generations of objects
									}
								}
							)
						}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access7[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion

			#pragma region Using of "Principal Self SID" in ACE
			auto [result8, granted_access8, access_status8, granted_access_string8] = check_access(
				L"Using of 'Principal Self SID' in ACE",
				XTOKEN::Create(
					XSID::CurrentUser,
					fiction_group
				),
				{
					fiction_owner,
					{{
						XACCESS_ALLOWED_ACE(
							XSID::PlaceholderPrincipalSelf,
							(DWORD)FILE_ALL_ACCESS
						)
					}}
				},
				FILE_ALL_ACCESS,
				false,
				std::nullopt,
				fiction_group // The "PrincipalSelf" in all ACEs would be replaced by this SID
			);

			Assert::AreEqual(granted_access8[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion

			#pragma region Audit: common audit message
			// NOTE: in order to generate any audit messages the calling PROCESS token must have "SeAuditPrivilege" enabled.
			// In this test we set "SeAuditPrivilege" in process token in "TEST_CLASS_INITIALIZE" function.
			// Privileges in the token participating in access checking does not matter.
			auto [result9, granted_access9, access_status9, granted_access_string9] = check_access(
				L"Audit: common audit message",
				XTOKEN::Create(
					XSID::CurrentUser,
					fiction_group
				),
				{
					fiction_owner,
					{{
						XACCESS_DENIED_ACE(
							XSID::CurrentUser,
							(DWORD)FILE_READ_ACCESS
						),
						XACCESS_ALLOWED_ACE(
							fiction_group,
							(DWORD)FILE_ALL_ACCESS
						)
					}},
					{{
							// Does not matter which flags to put here: if a mask is in "desired access" then logging would be performed.
							// In case access was denied (as in this case) it would be "denied message".
							XSYSTEM_AUDIT_ACE(
								// Even if we put "Everyone" here audit message have a chance to be suspended.
								// The audit message would be generated	only if the SID from SYSTEM_AUDIT_ACE exists 
								// in user's token. So, if there is no "Everyone" SID in token then no audit messages 
								/// would be generated for "XSYSTEM_AUDIT_ACE(Everyone)".
								fiction_group,
								(DWORD)FILE_WRITE_ACCESS,
								{ ByteBitsMeaningAceFlags, { L"SUCCESSFUL_ACCESS_ACE_FLAG", L"FAILED_ACCESS_ACE_FLAG" } }
							)
						}}
				},
				FILE_READ_ACCESS | FILE_WRITE_ACCESS
			);

			Assert::AreEqual(granted_access9[0], (DWORD)FILE_WRITE_ACCESS);
			#pragma endregion

			#pragma region Audit: missing FAILED_ACCESS_ACE_FLAG flag
			auto [result10, granted_access10, access_status10, granted_access_string10] = check_access(
				L"Audit: missing FAILED_ACCESS_ACE_FLAG flag",
				XTOKEN::Create(
					XSID::CurrentUser,
					fiction_group
				),
				{
					fiction_owner,
					{{
						XACCESS_DENIED_ACE(
							XSID::CurrentUser,
							(DWORD)FILE_READ_ACCESS
						),
						XACCESS_ALLOWED_ACE(
							fiction_group,
							(DWORD)FILE_ALL_ACCESS
						)
					}},
					{{
							// Audit message would not be generated due to missing "FAILED_ACCESS_ACE_FLAG" flag
							XSYSTEM_AUDIT_ACE(
								fiction_group,
								(DWORD)FILE_WRITE_ACCESS,
								{ ByteBitsMeaningAceFlags, { L"SUCCESSFUL_ACCESS_ACE_FLAG" } }
							)
						}}
				},
				FILE_READ_ACCESS | FILE_WRITE_ACCESS
			);

			Assert::AreEqual(granted_access10[0], (DWORD)FILE_WRITE_ACCESS);
			#pragma endregion

			#pragma region Audit: conditional audit message
			auto [result11, granted_access11, access_status11, granted_access_string11] = check_access(
				L"Audit: conditional audit message",
				XTOKEN::Create(
					XSID::CurrentUser,
					fiction_group,
					{},
					{},
					std::nullopt,
					{
						{{L"Title", { L"VP" }}}
					}
				),
				{
					fiction_owner,
					{{
						XACCESS_DENIED_ACE(
							XSID::CurrentUser,
							(DWORD)FILE_READ_ACCESS
						),
						XACCESS_ALLOWED_ACE(
							fiction_group,
							(DWORD)FILE_ALL_ACCESS
						)
					}},
					{{
						XSYSTEM_AUDIT_CALLBACK_ACE(
							fiction_group,
							(DWORD)FILE_WRITE_ACCESS,
							XUser(L"Title") == L"VP"
						)
					}}
				},
				FILE_READ_ACCESS | FILE_WRITE_ACCESS
			);

			Assert::AreEqual(granted_access11[0], (DWORD)FILE_WRITE_ACCESS);
			#pragma endregion
		}

		TEST_METHOD(FILE_EXAMPLE)
		{
			// How system creates DACL for new objects
			// https://docs.microsoft.com/en-us/windows/win32/secauthz/dacl-for-a-new-object

			#pragma region Check directory exists and remove it if necessary
			auto current = std::filesystem::current_path();

			if (std::filesystem::exists(current / "inherited"))
				std::filesystem::remove_all(current / "inherited");
			#pragma endregion

			#pragma region Create a sample directory with a default security descriptor
			if (!std::filesystem::create_directory(current / "inherited"))
				throw std::exception("Cannot make 'inherited' directory");
			#pragma endregion

			#pragma region Change DACL for the newly created directory
			XSD sd{
				XSID::CurrentUser,
				{{
					XACCESS_ALLOWED_ACE(
						XSID::Everyone,
						(DWORD)FILE_ALL_ACCESS
					),
				}}
			};

			bin_t bin = (bin_t)sd;

			BOOL result = SetFileSecurity(L"inherited", DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)bin.data());
			if (FALSE == result)
			{
				std::stringstream stream;
				stream << "Error on changing SD: " << GetLastError();

				throw std::exception(stream.str().c_str());
			}
			#pragma endregion

			#pragma region Make a token with "default DACL" and create a subdirectory with the token
			auto token = XTOKEN::Create(
				fiction_owner,
				fiction_group,
				{
					{ L"SeChangeNotifyPrivilege" } // Bypass traverse checking
				},
				{ XSID::Everyone }, // Need this group in order to access root directory
				std::nullopt,
				std::nullopt,
				std::nullopt,
				std::nullopt,
				{},
				std::nullopt,
				{ {
					XACCESS_ALLOWED_ACE(
						XSID::Everyone,
						(DWORD)FILE_ALL_ACCESS,
						{ ByteBitsMeaningAceFlags, { L"OBJECT_INHERIT_ACE", L"CONTAINER_INHERIT_ACE" } }
					),
					XACCESS_ALLOWED_ACE(
						XSID::PlaceholderPrincipalSelf, // Requires separate parameter during access check
						{ DwordMeaningFile, { L"GENERIC_ALL" } },
						{ ByteBitsMeaningAceFlags, { L"INHERIT_ONLY_ACE", L"OBJECT_INHERIT_ACE", L"CONTAINER_INHERIT_ACE" } }
					),
					XACCESS_ALLOWED_ACE(
						XSID::PlaceholderCreatorOwner, // Substitute with "Owner" from active token
						{ DwordMeaningFile, { L"GENERIC_ALL" } },
						{ ByteBitsMeaningAceFlags, { L"INHERIT_ONLY_ACE", L"OBJECT_INHERIT_ACE", L"CONTAINER_INHERIT_ACE" } }
					),
					XACCESS_ALLOWED_ACE(
						XSID::PlaceholderCreatorGroup, // Substitute with "PrimaryGroup" from active token
						{ DwordMeaningFile, { L"GENERIC_ALL" } },
						{ ByteBitsMeaningAceFlags, { L"INHERIT_ONLY_ACE", L"OBJECT_INHERIT_ACE", L"CONTAINER_INHERIT_ACE" } }
					),
					XACCESS_ALLOWED_ACE(
						XSID::PlaceholderOwnerServer, // Disapears from final DACL
						{ DwordMeaningFile, { L"GENERIC_ALL" } },
						{ ByteBitsMeaningAceFlags, { L"INHERIT_ONLY_ACE", L"OBJECT_INHERIT_ACE", L"CONTAINER_INHERIT_ACE" } }
					),
					XACCESS_ALLOWED_ACE(
						XSID::PlaceholderGroupServer,  // Disapears from final DACL
						{ DwordMeaningFile, { L"GENERIC_ALL" } },
						{ ByteBitsMeaningAceFlags, { L"INHERIT_ONLY_ACE", L"OBJECT_INHERIT_ACE", L"CONTAINER_INHERIT_ACE" } }
					)
				} }
			);

			HANDLE dup_token;
			if (FALSE == DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityDelegation, TokenImpersonation, &dup_token))
				throw std::exception("Cannot duplicate token");

			if (FALSE == SetThreadToken(nullptr, dup_token))
				throw std::exception("Cannot set token for thread");

			if (!std::filesystem::create_directory(current / "inherited/subdirectory"))
				throw std::exception("Cannot make 'inherited' directory");

			#pragma region Create a file using "manually made" token
			// The "PlaceholderCreatorOwner" and "PlaceholderCreatorGroup" values
			// are from "manually made" token. But a system also append values from "process token" somehow.
			std::ofstream(current / "inherited/subdirectory/file1.txt");
			#pragma endregion

			SetThreadToken(nullptr, nullptr); // Set back default token for current thread
			#pragma endregion

			#pragma region Get security descriptor from newly created file and store it to XML
			auto sd_file1 = XSD::GetFromFileObject(L"inherited/subdirectory/file1.txt");
			XSave(sd_file1, L"sd_file1.xml");
			#pragma endregion

			#pragma region Create a new file inside the subfolder using "default values"
			// Now on the file we will have a correctly set substitutes for
			// "PlaceholderCreatorOwner" and "PlaceholderCreatorGroup".
			// NOTE: all these values came from PROCESS token, not from the
			// token we manually made before (with default DACL).
			std::ofstream(current / "inherited/subdirectory/file2.txt");
			#pragma endregion
		}

		TEST_METHOD(INTEGRITY_CHECK)
		{
			#pragma region The "null DACL" with low integrity level in token
			// Access the security descriptor with "null DACL" (all SIDs allowed), but making a token with "UntrustedMandatoryLevel"
			// and at the same time security descriptor has "SystemMandatoryLevel" (with all flags set). 
			auto [result1, granted_access1, access_status1, granted_access_string1] = check_access(
				L"The 'null DACL' with low integrity level in token",
				XTOKEN::Create(
					XSID::CurrentUser,
					fiction_group,
					{},
					{
						{ XSID::UntrustedMandatoryLevel, { SidAndAttributesMeaningDefault, { L"SE_GROUP_INTEGRITY", L"SE_GROUP_INTEGRITY_ENABLED" } }}
					}
				),
				{
					fiction_owner,
					std::nullopt,
					{{
						XSYSTEM_MANDATORY_LABEL_ACE(
							XSID::SystemMandatoryLevel,
							{ DwordMeaningMandatoryLabel, { L"SYSTEM_MANDATORY_LABEL_NO_WRITE_UP", L"SYSTEM_MANDATORY_LABEL_NO_READ_UP", L"SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP" } }
						)
					}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access1[0], (DWORD)0);

			// Same configuration, but with "SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0" in SD and access requested in only FILE_READ_DATA.
			// The access would be granted, even for "UntrustedMandatoryLevel" in token.
			auto [result1_1, granted_access1_1, access_status1_1, granted_access_string1_1] = check_access(
				L"The 'null DACL' with low integrity level in token but with 'SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0'",
				XTOKEN::Create(
					XSID::CurrentUser,
					fiction_group,
					{},
					{
						{ XSID::UntrustedMandatoryLevel, { SidAndAttributesMeaningDefault, { L"SE_GROUP_INTEGRITY", L"SE_GROUP_INTEGRITY_ENABLED" } }}
					}
				),
				{
					fiction_owner,
					std::nullopt,
					{{
						XSYSTEM_MANDATORY_LABEL_ACE(
							XSID::SystemMandatoryLevel,
							{ DwordMeaningMandatoryLabel, { L"SYSTEM_MANDATORY_LABEL_NO_WRITE_UP", L"SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP" } }
						)
					}}
				},
				FILE_READ_DATA
			);

			Assert::AreEqual(granted_access1_1[0], (DWORD)FILE_READ_DATA);

			// Same configuration, but with "SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0" in SD and access requested in only FILE_READ_DATA.
			// But in this case in access checking function we do not use "generic rights mapping" and if the "mapping" is not used
			// the access check would be performed again using only two integrity levels comparision (no check for "SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0").
			auto [result1_2, granted_access1_2, access_status1_2, granted_access_string1_2] = check_access(
				L"The 'null DACL' with low integrity level in token but with 'SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0' but without 'mapping'",
				XTOKEN::Create(
					XSID::CurrentUser,
					fiction_group,
					{},
					{
						{ XSID::UntrustedMandatoryLevel, { SidAndAttributesMeaningDefault, { L"SE_GROUP_INTEGRITY", L"SE_GROUP_INTEGRITY_ENABLED" } }}
					}
				),
				{
					fiction_owner,
					std::nullopt,
					{{
						XSYSTEM_MANDATORY_LABEL_ACE(
							XSID::SystemMandatoryLevel,
							{ DwordMeaningMandatoryLabel, { L"SYSTEM_MANDATORY_LABEL_NO_WRITE_UP", L"SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP" } }
						)
					}}
				},
				FILE_READ_DATA,
				true // Flag for "not to use generic rights mapping"
			);

			Assert::AreEqual(granted_access1_2[0], (DWORD)0);

			// Same input as in previous case, but now we set 0 to "mandatory policy flags" in token.
			// It allows completely bypass any integrity checks and again check would be done for "null DACL" only (all SIDs allowed).
			auto [result1_3, granted_access1_3, access_status1_3, granted_access_string1_3] = check_access(
				L"The 'null DACL' with low integrity level in token but with 'SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0' but without 'mapping' and 'mandatory policy flags = 0'",
				XTOKEN::Create(
					XSID::CurrentUser,
					fiction_group,
					{},
					{
						{ XSID::UntrustedMandatoryLevel, { SidAndAttributesMeaningDefault, { L"SE_GROUP_INTEGRITY", L"SE_GROUP_INTEGRITY_ENABLED" } }}
					},
					std::nullopt,
					std::nullopt,
					std::nullopt,
					std::nullopt,
					{},
					(DWORD)0 // Mandatory policy flags
				),
				{
					fiction_owner,
					std::nullopt,
					{{
						XSYSTEM_MANDATORY_LABEL_ACE(
							XSID::SystemMandatoryLevel,
							{ DwordMeaningMandatoryLabel, { L"SYSTEM_MANDATORY_LABEL_NO_WRITE_UP", L"SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP" } }
						)
					}}
				},
				FILE_ALL_ACCESS,
				true // Flag for "not to use generic rights mapping"
			);

			Assert::AreEqual(granted_access1_3[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion

			#pragma region Administrative privileges on token with low level
			//
			// Certain administrative Windows privileges can be assigned to an access token only with at least a high integrity 
			// level.If the access token integrity level is less than high, then specific administrative privileges are not allowed 
			// and are removed from the access token (or just set to 0). The administrative privileges associated with a high integrity level are:
			//   SeCreateTokenPrivilege
			//   SeTcbPrivilege
			//   SeTakeOwnershipPrivilege
			//   SeLoadDriverPrivilege
			//   SeBackupPrivilege
			//   SeRestorePrivilege
			//   SeDebugPrivilege
			//   SeImpersonatePrivilege
			//   SeRelabelPrivilege
			//   SeDelegateSessionUserImpersonatePrivilege
			//
			auto token = XTOKEN::Create(
				XSID::CurrentUser,
				fiction_group,
				{
					{ L"SeCreateTokenPrivilege" },
					{ L"SeTcbPrivilege" },
					{ L"SeTakeOwnershipPrivilege" },
					{ L"SeLoadDriverPrivilege" },
					{ L"SeBackupPrivilege" },
					{ L"SeRestorePrivilege" },
					{ L"SeDebugPrivilege" },
					{ L"SeImpersonatePrivilege" },
					{ L"SeRelabelPrivilege" },
					{ L"SeDelegateSessionUserImpersonatePrivilege" }
				},
				{
					{ XSID::MediumMandatoryLevel, { SidAndAttributesMeaningDefault, { L"SE_GROUP_INTEGRITY", L"SE_GROUP_INTEGRITY_ENABLED" } }}
				}
				);

			DWORD attributes = 0;

			for (auto&& element : XTOKEN::GetTokenInfo<TokenPrivileges>(token))
				attributes += (DWORD)*element.Attributes;

			Assert::AreEqual(attributes, (DWORD)0);

			// It is also not able to set these privileges to any value other than 0
			auto change_result = XTOKEN::ChangePrivileges(
				{
					L"SeCreateTokenPrivilege",
					L"SeTcbPrivilege",
					L"SeTakeOwnershipPrivilege",
					L"SeLoadDriverPrivilege",
					L"SeBackupPrivilege",
					L"SeRestorePrivilege",
					L"SeDebugPrivilege",
					L"SeImpersonatePrivilege",
					L"SeRelabelPrivilege",
					L"SeDelegateSessionUserImpersonatePrivilege"
				},
				token,
				SE_PRIVILEGE_ENABLED
			);

			Assert::AreEqual(change_result, TRUE);

			for (auto&& element : XTOKEN::GetTokenInfo<TokenPrivileges>(token))
				attributes += (DWORD)*element.Attributes;

			Assert::AreEqual(attributes, (DWORD)0);

			// And it is do possible to set these privileges on token with at least "HighMandatoryLevel"
			auto token_high = XTOKEN::Create(
				XSID::CurrentUser,
				fiction_group,
				{
					{ L"SeCreateTokenPrivilege" },
					{ L"SeTcbPrivilege" },
					{ L"SeTakeOwnershipPrivilege" },
					{ L"SeLoadDriverPrivilege" },
					{ L"SeBackupPrivilege" },
					{ L"SeRestorePrivilege" },
					{ L"SeDebugPrivilege" },
					{ L"SeImpersonatePrivilege" },
					{ L"SeRelabelPrivilege" },
					{ L"SeDelegateSessionUserImpersonatePrivilege" }
				},
				{
					{ XSID::HighMandatoryLevel, { SidAndAttributesMeaningDefault, { L"SE_GROUP_INTEGRITY", L"SE_GROUP_INTEGRITY_ENABLED" } }}
				}
				);

			bool enabled = true;

			for (auto&& element : XTOKEN::GetTokenInfo<TokenPrivileges>(token_high))
				enabled &= (SE_PRIVILEGE_ENABLED == (DWORD)*element.Attributes);

			Assert::AreEqual(enabled, true);
			#pragma endregion
		}

		TEST_METHOD(CONDITIONAL)
		{
			#pragma region [MS-DTYP] 2.4.4.17.9 Example 1: Attributes in Simple Form
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
			#pragma endregion

			#pragma region [MS-DTYP] 2.4.4.17.9 Example 2: Prefixed Attribute Names and Multiple Terms
			auto [result2, granted_access2, access_status2, granted_access_string2] = check_access(
				L"[MS-DTYP] 2.4.4.17.9 Example 2: Prefixed Attribute Names and Multiple Terms",
				XTOKEN::Create(
					XSID::CurrentUser,
					XSID::Everyone,
					{},
					{},
					std::nullopt,
					{
						{{L"smartcard", { 1 }}}
					},
					{
						{{L"managed", { 1 }}}
					}
				),
				{
					fiction_owner,
					{{
						XACCESS_ALLOWED_CALLBACK_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS,
							((XUser(L"smartcard") == 1) || (XDevice(L"managed") == 1)) && XAny_of(XResource(L"dept"), XComposite({ L"Sales", L"HR" }))
							//// Comment prev line and uncomment next line if you want to test with data directly from [MS-DTYP]
							//std::nullopt, from_hex_codes(L"61 72 74 78 f9 12 00 00 00 73 00 6d 00 61 00 72 00 74 00 63 00 61 00 72 00 64 00 04 01 00 00 00 00 00 00 00 03 02 80 fb 0e 00 00 00 6d 00 61 00 6e 00 61 00 67 00 65 00 64 00 04 01 00 00 00 00 00 00 00 03 02 80 a1 fa 08 00 00 00 64 00 65 00 70 00 74 00 50 18 00 00 00 10 0a 00 00 00 53 00 61 00 6c 00 65 00 73 00 10 04 00 00 00 48 00 52 00 88 a0 00 00 00 00 00 00 00 00 00 00 00 00 00")
						)
					}},
					{{
						XSYSTEM_RESOURCE_ATTRIBUTE_ACE(
							{{ L"dept", { L"HR" }}}
						)
					}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access2[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion

			#pragma region [MS-DTYP] 2.4.4.17.9 Example 3: RHS Attribute Variables and SID-based Operators
			auto [result3, granted_access3, access_status3, granted_access_string3] = check_access(
				L"[MS-DTYP] 2.4.4.17.9 Example 3: RHS Attribute Variables and SID-based Operators",
				XTOKEN::Create(
					XSID::CurrentUser,
					XSID::Everyone,
					{},
					{ { XSID::SystemAdministrator } },
					std::nullopt,
					{
						{{L"clearanceLevel", { 10 }}}
					}
				),
				{
					fiction_owner,
					{{
						XACCESS_ALLOWED_CALLBACK_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS,
							// In [MS-DTYP] they use "Member_of(Composite(SID(BA))). But in fact "Member_of" works perfectly with single SID as well.
							XUser(L"clearanceLevel") >= XResource(L"requiredClearance") || XMember_of(XSID::SystemAdministrator)
							//// Comment prev line and uncomment next line if you want to test with data directly from [MS-DTYP]
							//std::nullopt, from_hex_codes(L"61 72 74 78 f9 1c 00 00 00 63 00 6c 00 65 00 61 00 72 00 61 00 6e 00 63 00 65 00 4c 00 65 00 76 00 65 00 6c 00 fa 22 00 00 00 72 00 65 00 71 00 75 00 69 00 72 00 65 00 64 00 43 00 6c 00 65 00 61 00 72 00 61 00 6e 00 63 00 65 00 85 50 15 00 00 00 51 10 00 00 00 01 02 00 00 00 00 00 05 20 00 00 00 20 02 00 00 89 a1 00 00 00")
						)
					}},
					{{
						XSYSTEM_RESOURCE_ATTRIBUTE_ACE(
							{{ L"requiredClearance", { 15 }}}
						)
					}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access3[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion

			#pragma region Multiple values in "user attribute"
			auto [result4, granted_access4, access_status4, granted_access_string4] = check_access(
				L"Multiple values in 'user attribute'",
				XTOKEN::Create(
					XSID::CurrentUser,
					XSID::Everyone,
					{},
					{},
					std::nullopt,
					{
						{
							// NOTE: multiple values allowed ONLY in "token attributes" (local, user and device).
							// Using multiple values in a "resource attribute" will lead to error during access check.
							{L"sids", { XSID::Administrators, XSID::Everyone }}
						}
					}
				),
				{
					fiction_owner,
					{{
						XACCESS_ALLOWED_CALLBACK_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS,
							XContains(XUser(L"sids"), XSID::Everyone)
						)
					}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access4[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion

			#pragma region Using SID in "resource attribute" (undocumented format)
			auto [result5, granted_access5, access_status5, granted_access_string5] = check_access(
				L"Using SID in 'resource attribute' (undocumented format)",
				XTOKEN::Create(XSID::CurrentUser),
				{
					fiction_owner,
					{{
						XACCESS_ALLOWED_CALLBACK_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS,
							XResource(L"sid") == XSID::Administrators
						)
					}},
					{{
						XSYSTEM_RESOURCE_ATTRIBUTE_ACE(
							{{ L"sid", { XSID::Administrators }}}
						)
					}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access5[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion

			#pragma region Using "octet string" (binary) in "resource attribute" (undocumented format)
			auto [result6, granted_access6, access_status6, granted_access_string6] = check_access(
				L"Using 'octet string' (binary) in 'resource attribute' (undocumented format)",
				XTOKEN::Create(XSID::CurrentUser),
				{
					fiction_owner,
					{{
						XACCESS_ALLOWED_CALLBACK_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS,
							XResource(L"octets") == bin_t{ 1, 2, 3, 4, 5 }
						)
					}},
					{{
						XSYSTEM_RESOURCE_ATTRIBUTE_ACE(
							{{ L"octets", { bin_t{ 1, 2, 3, 4, 5 } }}}
						)
					}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access6[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion

			#pragma region Using an attribute as a simple boolean value
			auto [result7, granted_access7, access_status7, granted_access_string7] = check_access(
				L"Using an attribute as a simple boolean value",
				XTOKEN::Create(XSID::CurrentUser),
				{
					fiction_owner,
					{{
						XACCESS_ALLOWED_CALLBACK_ACE(
							XSID::Everyone,
							(DWORD)FILE_ALL_ACCESS,
							XResource(L"boolean")
						)
					}},
					{{
						XSYSTEM_RESOURCE_ATTRIBUTE_ACE(
							{{ L"boolean", { true }}}
						)
					}}
				},
				FILE_ALL_ACCESS
			);

			Assert::AreEqual(granted_access7[0], (DWORD)FILE_ALL_ACCESS);
			#pragma endregion
		}

		TEST_METHOD(OBJECT_ACE)
		{
			auto guid1 = (GUID)XGUID::Create();

			auto guid2 = (GUID)XGUID::Create();
			auto guid3 = (GUID)XGUID::Create();
			auto guid4 = (GUID)XGUID::Create();

			auto guid5 = (GUID)XGUID::Create();
			auto guid6 = (GUID)XGUID::Create();
			auto guid7 = (GUID)XGUID::Create();

			auto guid8 = (GUID)XGUID::Create();

			//                     --------- 
			//                     | guid1 | 
			//                     --------- 
			//                         |
			//              ___________|_________________
			//             /                \            \
			//            /                  \            \
			//      ---------               ---------    ---------
			//      | guid2 |               | guid5 |    | guid8 |
			//      ---------               ---------    ---------
			//    /           \           /           \
			//   /             \         /             \
			// ---------    ---------  ---------    ---------
			// | guid3 |    | guid4 |  | guid6 |    | guid7 |
			// ---------    ---------  ---------    ---------

			std::vector<OBJECT_TYPE_LIST> list = {
				{ 0, 0, &guid1 },

				{ 1, 0,	&guid2 },
				{ 2, 0,	&guid3 },
				{ 2, 0,	&guid4 },

				{ 1, 0,	&guid5 },
				{ 2, 0,	&guid6 },
				{ 2, 0,	&guid7 },

				{ 1, 0,	&guid8 }
			};

			XSD sd{
				fiction_owner,
				{{
					XACCESS_DENIED_OBJECT_ACE(
						XSID::Everyone,
						{ "00001", DwordMeaningActiveDirectoryObject },
						guid4
					),
					XACCESS_DENIED_OBJECT_ACE(
						XSID::Everyone,
						{ "00010", DwordMeaningActiveDirectoryObject },
						guid7
					),
					XACCESS_DENIED_OBJECT_ACE(
						XSID::Everyone,
						{ "00100", DwordMeaningActiveDirectoryObject },
						guid8
					),
					XACCESS_ALLOWED_OBJECT_ACE(
						XSID::Everyone,
						{ "00011", DwordMeaningActiveDirectoryObject },
						guid2
					),
					XACCESS_ALLOWED_OBJECT_ACE(
						XSID::Everyone,
						{ "11000", DwordMeaningActiveDirectoryObject },
						guid3
					),
					XACCESS_ALLOWED_OBJECT_ACE(
						XSID::Everyone,
						{ "11000", DwordMeaningActiveDirectoryObject },
						guid4
					),
					XACCESS_ALLOWED_OBJECT_ACE(
						XSID::Everyone,
						{ "10001", DwordMeaningActiveDirectoryObject },
						guid5
					),
					XACCESS_ALLOWED_OBJECT_ACE(
						XSID::Everyone,
						{ "10010", DwordMeaningActiveDirectoryObject },
						guid6
					),
					XACCESS_ALLOWED_OBJECT_ACE(
						XSID::Everyone,
						{ "10010", DwordMeaningActiveDirectoryObject },
						guid7
					),
					XACCESS_ALLOWED_OBJECT_ACE(
						XSID::Everyone,
						{ "00110", DwordMeaningActiveDirectoryObject },
						guid8
					)
				}},
				std::nullopt,
				fiction_group
			};

			auto [result, granted_access, access_status, granted_access_string] = check_access(
				L"Object List test example",
				XTOKEN::Create(XSID::CurrentUser),
				sd,
				(DWORD)XBITSET<32>{ "11111", DwordMeaningActiveDirectoryObject },
				false,
				list
			);

			// Access checking process for such ACEs described in [MS-ADTS] 5.1.3.3.3
			// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3da5080d-de25-4ac8-9f2b-982709253dfb
			//
			// guid1 (no direct "allows" for the root and for root the rule with "equal siblings" have no influence)
			Assert::AreEqual(granted_access_string[0], std::string("00000000000000000000000000000000"));

			// guid2 ("allows" from direct ACE plus all descendant nodes have equal rights, "denies" came from guid4)
			Assert::AreEqual(granted_access_string[1], std::string("00000000000000000000000000011010"));

			// guid3 ("allows" came from direct ACE plus from ancendant node guid2, no "denies")
			Assert::AreEqual(granted_access_string[2], std::string("00000000000000000000000000011011"));

			// guid4 ("allows" came from direct ACE plus from ancendant node guid2, "denies" from direct ACE for guid4)
			Assert::AreEqual(granted_access_string[3], std::string("00000000000000000000000000011010"));

			// guid5 ("allows" came from direct ACE plus descendant nodes (even if descendant nodes have equal "allows" for guid7 we have "denies" and that is why the nodes became "not equal"), "denies" from direct ACE for guid7)
			Assert::AreEqual(granted_access_string[4], std::string("00000000000000000000000000010001"));

			// guid6 ("allows" came from direct ACE plus ancendant node guid5, no "denies")
			Assert::AreEqual(granted_access_string[5], std::string("00000000000000000000000000010011"));

			// guid7 ("allows" came from direct ACE plus ancendant node guid5, "denies" came from direct ACE for guid7)
			Assert::AreEqual(granted_access_string[6], std::string("00000000000000000000000000010001"));

			// guid8 ("allows" came from direct ACE, "denies" from direct ACE)
			Assert::AreEqual(granted_access_string[7], std::string("00000000000000000000000000000010"));
		}
	};
}
