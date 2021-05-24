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
	//********************************************************************************************
	struct XSID
	{
		XSID() = delete;
		~XSID() = default;

		XSID(const wchar_t*);
		XSID(const std::wstring&);

		XSID(const BYTE revision, const DWORD identifierAuthority, const std::vector<DWORD>& subAuthority);

		XSID(const unsigned char*);
		XSID(const bin_t&);
		XSID(const msxml_et&);

		explicit operator bin_t() const;
		explicit operator xml_t() const;

		static XSID ConstructForCurrentDomain(const DWORD&);

		bool operator==(const XSID&) const;

		std::wstring commonName() const;
		std::wstring stringRepresentation() const;

		#pragma region Static declarations for well-known SIDs
		static const XSID Nobody;
		static const XSID Everyone;
		static const XSID Anonymous;

		static const XSID PlaceholderPrincipalSelf;
		static const XSID PlaceholderCreatorOwner;
		static const XSID PlaceholderCreatorGroup;
		static const XSID PlaceholderOwnerServer;
		static const XSID PlaceholderGroupServer;

		static const XSID LocalSystem;

		static const XSID Administrators;
		static const XSID Users;
		static const XSID Guests;

		static const XSID CurrentUser;

		static const XSID SystemAdministrator;
		static const XSID SystemGuest;

		static const XSID DomainAdministrators;
		static const XSID DomainUsers;

		static const XSID UntrustedMandatoryLevel;
		static const XSID LowMandatoryLevel;
		static const XSID MediumMandatoryLevel;
		static const XSID MediumPlusMandatoryLevel;
		static const XSID HighMandatoryLevel;
		static const XSID SystemMandatoryLevel;
		static const XSID ProtectedProcessMandatoryLevel;
		static const XSID SecureProcessMandatoryLevel;
		#pragma endregion

		BYTE Revision = 0;
		DWORD IdentifierAuthority = 0;
		std::vector<DWORD> SubAuthority;

		size_t Length = 0;
	};
	//********************************************************************************************
	const XSID XSID::Nobody = L"S-1-0-0";
	const XSID XSID::Everyone = L"S-1-1-0";
	const XSID XSID::Anonymous = L"S-1-5-7";

	const XSID XSID::PlaceholderPrincipalSelf = L"S-1-5-10";
	const XSID XSID::PlaceholderCreatorOwner = L"S-1-3-0";
	const XSID XSID::PlaceholderCreatorGroup = L"S-1-3-1";
	const XSID XSID::PlaceholderOwnerServer = L"S-1-3-2";
	const XSID XSID::PlaceholderGroupServer = L"S-1-3-3";

	const XSID XSID::LocalSystem = L"S-1-5-18";

	const XSID XSID::Administrators = L"S-1-5-32-544";
	const XSID XSID::Users = L"S-1-5-32-546";
	const XSID XSID::Guests = L"S-1-5-32-546";

	const XSID XSID::CurrentUser = XSID::ConstructForCurrentDomain(0);

	const XSID XSID::SystemAdministrator = XSID::ConstructForCurrentDomain(500);
	const XSID XSID::SystemGuest = XSID::ConstructForCurrentDomain(501);

	const XSID XSID::DomainAdministrators = XSID::ConstructForCurrentDomain(512);
	const XSID XSID::DomainUsers = XSID::ConstructForCurrentDomain(513);

	const XSID XSID::UntrustedMandatoryLevel = L"S-1-16-0";
	const XSID XSID::LowMandatoryLevel = L"S-1-16-4096";
	const XSID XSID::MediumMandatoryLevel = L"S-1-16-8192";
	const XSID XSID::MediumPlusMandatoryLevel = L"S-1-16-8448";
	const XSID XSID::HighMandatoryLevel = L"S-1-16-12288";
	const XSID XSID::SystemMandatoryLevel = L"S-1-16-16384";
	const XSID XSID::ProtectedProcessMandatoryLevel = L"S-1-16-20480";
	const XSID XSID::SecureProcessMandatoryLevel = L"S-1-16-28672";
	//********************************************************************************************
	XSID XSID::ConstructForCurrentDomain(const DWORD& value)
	{
		HANDLE token;

		if(!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &token))
			throw std::exception("GetCurrentDomain: cannot get current process token");

		token_guard guard(token);

		DWORD size = 0;

		if(!GetTokenInformation(token, TokenUser, nullptr, size, &size))
		{
			DWORD error = GetLastError();
			if((ERROR_INSUFFICIENT_BUFFER != error) && (ERROR_BAD_LENGTH != error))
				throw std::exception("GetCurrentDomain: unexpected error");
		}

		std::unique_ptr<TOKEN_USER> user(static_cast<PTOKEN_USER>(::operator new(size)));

		if(!GetTokenInformation(token, TokenUser, user.get(), size, &size))
			throw std::exception("GetCurrentDomain: unexpected error");

		XSID sid((unsigned char*)user->User.Sid);

		// If "value == 0" we will return XSID for the current user
		if(value)
		{
			if((1 != sid.Revision) || (5 != sid.IdentifierAuthority) || (21 != sid.SubAuthority[0]))
				throw std::exception("GetCurrentDomain: incorect User's XSID structure");

			sid.SubAuthority[sid.SubAuthority.size() - 1] = value;
		}

		return sid;
	}
	//********************************************************************************************
	XSID::XSID(const std::wstring& string)
	{
		if(string.size() < 2)
			throw std::exception("XSID: invalid XSID string structure");

		std::vector<DWORD> temp;

		auto begin = string.begin();
		auto end = string.end();

		if((string[0] == L'S') && (string[1] == L'-'))
			begin += 2;

		std::wstringstream stream(std::wstring(begin, end));
		std::wstring item;

		while(std::getline(stream, item, L'-'))
		{
			std::wstringstream item_stream(item);

			DWORD value = 0;
			item_stream >> value;

			temp.push_back(value);
		}

		if(temp.size() < 3)
			throw std::exception("XSID: invalid XSID string structure");

		Revision = ((BYTE*)&temp[0])[0];
		IdentifierAuthority = temp[1];
		std::copy(temp.begin() + 2, temp.end(), std::back_inserter(SubAuthority));
	}
	//********************************************************************************************
	XSID::XSID(const wchar_t* string) : XSID(std::wstring(string))
	{
	}
	//********************************************************************************************
	XSID::XSID(const BYTE revision, const DWORD identifierAuthority, const std::vector<DWORD>& subAuthority) :	Revision(revision),
																												IdentifierAuthority(identifierAuthority),
																												SubAuthority(subAuthority)
	{
	}
	//********************************************************************************************
	XSID::XSID(const unsigned char* data)
	{
		#pragma region Initial check
		if(nullptr == data)
			throw std::exception("XSID: invalid input data");
		#pragma endregion

		#pragma region Initial variables
		DWORD* int_data = (DWORD*)data;
		#pragma endregion

		#pragma region Revision and SubAuthorityCount
		Revision = int_data[0] & 0x000000FF;
		DWORD SubAuthorityCount = (int_data[0] & 0x0000FF00) >> 8;
		#pragma endregion

		#pragma region IdentifierAuthority
		IdentifierAuthority = int_data[1];

		#pragma region Change "endian" for "IdentifierAuthority"
		BYTE temp = ((BYTE*)&IdentifierAuthority)[0];
		((BYTE*)&IdentifierAuthority)[0] = ((BYTE*)&IdentifierAuthority)[3];
		((BYTE*)&IdentifierAuthority)[1] = ((BYTE*)&IdentifierAuthority)[2];
		((BYTE*)&IdentifierAuthority)[3] = temp;
		#pragma endregion
		#pragma endregion

		#pragma region SubAuthority
		SubAuthority.clear();

		if(SubAuthorityCount)
		{
			SubAuthority.resize(SubAuthorityCount);
			memcpy(&SubAuthority[0], data + 2 * sizeof(DWORD), SubAuthorityCount * sizeof(DWORD));
		}
		#pragma endregion

		Length = (2 + SubAuthorityCount) * sizeof(DWORD);
	}
	//********************************************************************************************
	XSID::XSID(const bin_t& data)
	{
		#pragma region Initial variables
		DWORD* int_data = (DWORD*)(&data[0]);
		#pragma endregion

		#pragma region Revision and SubAuthorityCount
		Revision = int_data[0] & 0x000000FF;
		DWORD SubAuthorityCount = (int_data[0] & 0x0000FF00) >> 8;
		#pragma endregion

		#pragma region IdentifierAuthority
		IdentifierAuthority = int_data[1];

		#pragma region Change "endian" for "IdentifierAuthority"
		BYTE temp = ((BYTE*)&IdentifierAuthority)[0];
		((BYTE*)&IdentifierAuthority)[0] = ((BYTE*)&IdentifierAuthority)[3];
		((BYTE*)&IdentifierAuthority)[1] = ((BYTE*)&IdentifierAuthority)[2];
		((BYTE*)&IdentifierAuthority)[3] = temp;
		#pragma endregion
		#pragma endregion

		#pragma region SubAuthority
		SubAuthority.clear();

		if(SubAuthorityCount)
		{
			SubAuthority.resize(SubAuthorityCount);
			memcpy(&SubAuthority[0], &data[0] + 2 * sizeof(DWORD), SubAuthorityCount * sizeof(DWORD));
		}
		#pragma endregion

		Length = (2 + SubAuthorityCount) * sizeof(DWORD);
	}
	//********************************************************************************************
	XSID::operator bin_t() const
	{
		#pragma region Initial variables
		bin_t result;
		#pragma endregion

		#pragma region Allocating memory for output data
		result.resize((SubAuthority.size() + 2) * sizeof(DWORD));
		#pragma endregion

		#pragma region Initial variables
		DWORD* int_data = (DWORD*)(result.data());
		#pragma endregion

		#pragma region Revision and SubAuthorityCount
		int_data[0] = Revision;
		int_data[0] |= (SubAuthority.size() << 8);
		#pragma endregion

		#pragma region IdentifierAuthority
		int_data[1] = IdentifierAuthority;

		#pragma region Change "endian" for "IdentifierAuthority"
		BYTE temp = ((BYTE*)&(int_data[1]))[0];
		((BYTE*)&(int_data[1]))[0] = ((BYTE*)&(int_data[1]))[3];
		((BYTE*)&(int_data[1]))[1] = ((BYTE*)&(int_data[1]))[2];
		((BYTE*)&(int_data[1]))[3] = temp;
		#pragma endregion
		#pragma endregion

		#pragma region SubAuthority
		if(SubAuthority.empty() == false)
			memcpy(result.data() + 2 * sizeof(DWORD), &SubAuthority[0], SubAuthority.size() * sizeof(DWORD));
		#pragma endregion

		return result;
	}
	//********************************************************************************************
	XSID::XSID(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XSID: incorrect input XML");
		#pragma endregion

		#pragma region Revision
		msxml_et revision = xml->selectSingleNode(L"Revision");
		if(nullptr == revision)
			throw std::exception("XSID: cannot find 'Revision' in XML");

		Revision = _variant_t(revision->text);
		#pragma endregion

		#pragma region IdentifierAuthority
		msxml_et identifierAuthority = xml->selectSingleNode(L"IdentifierAuthority");
		if(nullptr == identifierAuthority)
			throw std::exception("XSID: cannot find 'IdentifierAuthority' in XML");

		IdentifierAuthority = _variant_t(identifierAuthority->text);
		#pragma endregion

		#pragma region SubAuthority
		msxml_nt subAuthorities = xml->selectNodes(L"SubAuthority");
		if(nullptr == subAuthorities)
			throw std::exception("XSID: cannot find 'SubAuthority' in XML");

		for(int i = 0; i < subAuthorities->length; i++)
			SubAuthority.push_back(_variant_t(subAuthorities->item[i]->text));
		#pragma endregion
	}
	//********************************************************************************************
	XSID::operator xml_t() const
	{
		return [&](msxml_dt xml, std::optional<const wchar_t*> root) -> msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XSID: invalid output XML");
			#pragma endregion

			#pragma region Root element
			msxml_et sid = xml->createElement(std::wstring(root.value_or(L"SID")).c_str());

			msxml_at commonName = xml->createAttribute(L"CommonName");

			commonName->value = (this->commonName()).c_str();
			sid->setAttributeNode(commonName);

			msxml_at stringRepresentation = xml->createAttribute(L"StringRepresentation");

			stringRepresentation->value = (this->stringRepresentation()).c_str();
			sid->setAttributeNode(stringRepresentation);
			#pragma endregion

			#pragma region Revision
			msxml_et revision = xml->createElement(L"Revision");

			revision->appendChild(xml->createTextNode(_variant_t(Revision).operator _bstr_t()));

			sid->appendChild(revision);
			#pragma endregion

			#pragma region IdentifierAuthority
			msxml_et identifierAuthority = xml->createElement(L"IdentifierAuthority");

			identifierAuthority->appendChild(xml->createTextNode(_variant_t(IdentifierAuthority).operator _bstr_t()));

			sid->appendChild(identifierAuthority);
			#pragma endregion

			#pragma region SubAuthority
			if(SubAuthority.empty() == false)
			{
				for(BYTE i = 0; i < SubAuthority.size(); i++)
				{
					msxml_et subAuthority = xml->createElement(L"SubAuthority");

					subAuthority->appendChild(xml->createTextNode(_variant_t(SubAuthority[i]).operator _bstr_t()));

					sid->appendChild(subAuthority);
				}
			}
			#pragma endregion

			return sid;
		};
	}
	//********************************************************************************************
	std::wstring XSID::commonName() const
	{
		#pragma region Initial variables
		SID_NAME_USE sidUsage;

		DWORD accountNameLength = 0;
		std::wstring accountName;

		DWORD domainNameLength = 0;
		std::wstring domainName;

		DWORD lastError = 0;
		#pragma endregion

		#pragma region Convert internal data to common XSID
		auto sid = this->operator XSEC::bin_t();
		#pragma endregion

		#pragma region First call to "LookupAccountSid"
		LookupAccountSid(NULL, sid.data(), NULL, &accountNameLength, NULL, &domainNameLength, &sidUsage);

		lastError = GetLastError();

		switch(lastError)
		{
			case ERROR_INSUFFICIENT_BUFFER:
				// Both lenghts are having "0" at end, but "wstring" already reserved it
				accountName.resize(accountNameLength - 1);
				domainName.resize(domainNameLength - 1);

				if(!LookupAccountSid(NULL, sid.data(), accountName.data(), &accountNameLength, domainName.data(), &domainNameLength, &sidUsage))
					return L"";

				if(accountNameLength && domainNameLength)
					return (domainName + std::wstring(L"\\") + accountName);
				else
				{
					if(accountNameLength)
						return accountName;
					else
						return domainName;
				}

				break;
			case ERROR_NONE_MAPPED:
			default:
				{
					if((IdentifierAuthority == 5) && (SubAuthority[0] == 5))
						return L"LOGON_ID";
					else
						return L"NONE_MAPPED";
				}
		}
		#pragma endregion
	}
	//********************************************************************************************
	std::wstring XSID::stringRepresentation() const
	{
		#pragma region Initial variables
		std::wstringstream stream;
		#pragma endregion

		#pragma region Get first part of representation
		stream << L"S-" << Revision << L"-" << IdentifierAuthority;
		#pragma endregion

		#pragma region Additional check
		if(SubAuthority.empty())
			return stream.str();
		#pragma endregion

		#pragma region SubAuthority
		for(auto&& element : SubAuthority)
			stream << L"-" << element;
		#pragma endregion

		return stream.str();
	}
	//********************************************************************************************
	bool XSID::operator==(const XSID& sid) const
	{
		return ((sid.Revision == Revision) && (sid.IdentifierAuthority == IdentifierAuthority) && (sid.SubAuthority == SubAuthority));
	}
	//********************************************************************************************
}
//********************************************************************************************
