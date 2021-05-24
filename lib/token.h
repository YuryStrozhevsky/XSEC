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
	#pragma region Class for working with TOKEN_GROUPS_AND_PRIVILEGES structure
	//****************************************************************************************
	struct XTOKEN_GROUPS_AND_PRIVILEGES
	{
		XTOKEN_GROUPS_AND_PRIVILEGES() = delete;
		~XTOKEN_GROUPS_AND_PRIVILEGES() = default;

		XTOKEN_GROUPS_AND_PRIVILEGES(
			const std::vector<XSID_AND_ATTRIBUTES>&,
			const std::vector<XSID_AND_ATTRIBUTES>&,
			const std::vector<XLUID_AND_ATTRIBUTES>&,
			const XLUID&
		);

		XTOKEN_GROUPS_AND_PRIVILEGES(const TOKEN_GROUPS_AND_PRIVILEGES&);
		XTOKEN_GROUPS_AND_PRIVILEGES(const msxml_et&);

		explicit operator xml_t() const;

		std::vector<XSID_AND_ATTRIBUTES> Sids;
		std::vector<XSID_AND_ATTRIBUTES> RestrictedSids;
		std::vector<XLUID_AND_ATTRIBUTES> Privileges;
		std::shared_ptr<XLUID> AuthenticationId;
	};
	//****************************************************************************************
	XTOKEN_GROUPS_AND_PRIVILEGES::XTOKEN_GROUPS_AND_PRIVILEGES(
		const std::vector<XSID_AND_ATTRIBUTES>& sids,
		const std::vector<XSID_AND_ATTRIBUTES>& restrictedSids,
		const std::vector<XLUID_AND_ATTRIBUTES>& privileges,
		const XLUID& authenticationId
	) : Sids(sids), RestrictedSids(restrictedSids), Privileges(privileges), AuthenticationId(std::make_shared<XLUID>(authenticationId))
	{
	}
	//****************************************************************************************
	XTOKEN_GROUPS_AND_PRIVILEGES::XTOKEN_GROUPS_AND_PRIVILEGES(const TOKEN_GROUPS_AND_PRIVILEGES& data)
	{
		for(DWORD i = 0; i < data.SidCount; i++)
			Sids.push_back(XSID_AND_ATTRIBUTES(data.Sids[i], SidAndAttributesMeaningDefault));

		if(nullptr != data.RestrictedSids)
		{
			for(DWORD i = 0; i < data.RestrictedSidCount; i++)
				RestrictedSids.push_back(XSID_AND_ATTRIBUTES(data.RestrictedSids[i], SidAndAttributesMeaningDefault));
		}

		for(DWORD i = 0; i < data.PrivilegeCount; i++)
			Privileges.push_back(XLUID_AND_ATTRIBUTES(data.Privileges[i]));

		AuthenticationId = std::make_shared<XLUID>(data.AuthenticationId);
	}
	//****************************************************************************************
	XTOKEN_GROUPS_AND_PRIVILEGES::XTOKEN_GROUPS_AND_PRIVILEGES(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: invalid input XML");
		#pragma endregion

		#pragma region Sids
		msxml_nt sids = xml->selectNodes(L"Sids/Sid");
		if(nullptr == sids)
			throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: cannot find 'Sids' XML node");

		for(long i = 0; i < sids->length; i++)
			Sids.push_back(XSID_AND_ATTRIBUTES(sids->item[i], SidAndAttributesMeaningDefault));
		#pragma endregion

		#pragma region RestrictedSids
		msxml_nt restrictedSids = xml->selectNodes(L"RestrictedSids/RestrictedSid");
		if(nullptr != restrictedSids)
		{
			for(long i = 0; i < restrictedSids->length; i++)
				RestrictedSids.push_back(XSID_AND_ATTRIBUTES(restrictedSids->item[i], SidAndAttributesMeaningDefault));
		}
		#pragma endregion

		#pragma region Privileges
		msxml_nt privileges = xml->selectNodes(L"Privileges/Privilege");
		if(nullptr == privileges)
			throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: cannot find 'Privileges' XML node");

		for(long i = 0; i < privileges->length; i++)
			Privileges.push_back(XLUID_AND_ATTRIBUTES(privileges->item[i]));
		#pragma endregion

		#pragma region AuthenticationId
		msxml_et authenticationId = xml->selectSingleNode(L"AuthenticationId");
		if(nullptr == authenticationId)
			throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: cannot find 'AuthenticationId' XML node");

		AuthenticationId = std::make_shared<XLUID>(authenticationId);
		#pragma endregion
	}
	//****************************************************************************************
	XTOKEN_GROUPS_AND_PRIVILEGES::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et tokenGroupsAndPrivileges = xml->createElement(std::wstring(root.value_or(L"TokenGroupsAndPrivileges")).c_str());
			if(nullptr == tokenGroupsAndPrivileges)
				throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: cannot create root XML node");
			#pragma endregion

			#pragma region Sids
			msxml_et sids = xml->createElement(L"Sids");
			if(nullptr == sids)
				throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: cannot create 'Sids' XML node");

			for(auto&& element : Sids)
				sids->appendChild(((xml_t)element)(xml, L"Sid"));

			tokenGroupsAndPrivileges->appendChild(sids);
			#pragma endregion

			#pragma region RestrictedSids
			if(RestrictedSids.empty() == false)
			{
				msxml_et restrictedSids = xml->createElement(L"RestrictedSids");
				if(nullptr == restrictedSids)
					throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: cannot create 'RestrictedSids' XML node");

				for(auto&& element : RestrictedSids)
					restrictedSids->appendChild(((xml_t)element)(xml, L"RestrictedSid"));

				tokenGroupsAndPrivileges->appendChild(restrictedSids);
			}
			#pragma endregion

			#pragma region Privileges
			msxml_et privileges = xml->createElement(L"Privileges");
			if(nullptr == privileges)
				throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: cannot create 'Privileges' XML node");

			for(auto&& element : Privileges)
				privileges->appendChild(((xml_t)element)(xml, L"Privilege"));

			tokenGroupsAndPrivileges->appendChild(privileges);
			#pragma endregion

			#pragma region AuthenticationId
			if(nullptr == AuthenticationId)
				throw std::exception("TOKEN_GROUPS_AND_PRIVILEGES: initialize data first");

			tokenGroupsAndPrivileges->appendChild(((xml_t)*AuthenticationId)(xml, L"AuthenticationId"));
			#pragma endregion

			return tokenGroupsAndPrivileges;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with TOKEN_ACCESS_INFORMATION structure
	//****************************************************************************************
	struct XTOKEN_ACCESS_INFORMATION
	{
		XTOKEN_ACCESS_INFORMATION() = delete;
		~XTOKEN_ACCESS_INFORMATION() = default;

		XTOKEN_ACCESS_INFORMATION(
			const XSID_AND_ATTRIBUTES_HASH&,
			const XSID_AND_ATTRIBUTES_HASH&,
			const std::vector<XLUID_AND_ATTRIBUTES>&,
			const XLUID&,
			const BYTE&,
			const SECURITY_IMPERSONATION_LEVEL&,
			const XBITSET<32>&,
			const XBITSET<32>&,
			const DWORD&,
			const XSID&,
			const XSID_AND_ATTRIBUTES_HASH&,
			const XSID&
		);

		XTOKEN_ACCESS_INFORMATION(const TOKEN_ACCESS_INFORMATION&);
		XTOKEN_ACCESS_INFORMATION(const msxml_et&);

		explicit operator xml_t() const;

		std::shared_ptr<XSID_AND_ATTRIBUTES_HASH> SidHash;
		std::shared_ptr<XSID_AND_ATTRIBUTES_HASH> RestrictedSidHash;
		std::vector<XLUID_AND_ATTRIBUTES> Privileges;

		std::shared_ptr<XLUID> AuthenticationId;
		BYTE Type = 0;
		SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
		std::shared_ptr<XBITSET<32>> MandatoryPolicy;

		std::shared_ptr<XBITSET<32>> Flags;

		DWORD AppContainerNumber = 0;

		std::shared_ptr<XSID> PackageSid;
		std::shared_ptr<XSID_AND_ATTRIBUTES_HASH> CapabilitiesHash;
		std::shared_ptr<XSID> TrustLevelSid;

		//PSECURITY_ATTRIBUTES_OPAQUE SecurityAttributes; // No information about this struct member
	};
	//****************************************************************************************
	XTOKEN_ACCESS_INFORMATION::XTOKEN_ACCESS_INFORMATION(
		const XSID_AND_ATTRIBUTES_HASH& sidHash,
		const XSID_AND_ATTRIBUTES_HASH& restrictedSidHash,
		const std::vector<XLUID_AND_ATTRIBUTES>& privileges,
		const XLUID& authenticationId,
		const BYTE& type,
		const SECURITY_IMPERSONATION_LEVEL& impersonationLevel,
		const XBITSET<32>& mandatoryPolicy,
		const XBITSET<32>& flags,
		const DWORD& appContainerNumber,
		const XSID& packageSid,
		const XSID_AND_ATTRIBUTES_HASH& capabilitiesHash,
		const XSID& trustLevelSid
	)
	{
		SidHash = std::make_shared<XSID_AND_ATTRIBUTES_HASH>(sidHash);
		RestrictedSidHash = std::make_shared<XSID_AND_ATTRIBUTES_HASH>(restrictedSidHash);
		Privileges = privileges;
		AuthenticationId = std::make_shared<XLUID>(authenticationId);
		Type = type;
		ImpersonationLevel = impersonationLevel;
		MandatoryPolicy = std::make_shared<XBITSET<32>>(mandatoryPolicy);
		Flags = std::make_shared<XBITSET<32>>(flags);
		AppContainerNumber = appContainerNumber;
		PackageSid = std::make_shared<XSID>(packageSid);
		CapabilitiesHash = std::make_shared<XSID_AND_ATTRIBUTES_HASH>(capabilitiesHash);
		TrustLevelSid = std::make_shared<XSID>(trustLevelSid);
	}
	//****************************************************************************************
	XTOKEN_ACCESS_INFORMATION::XTOKEN_ACCESS_INFORMATION(const TOKEN_ACCESS_INFORMATION& data)
	{
		SidHash = std::make_shared<XSID_AND_ATTRIBUTES_HASH>(*(data.SidHash), SidAndAttributesMeaningDefault);
		RestrictedSidHash = std::make_shared<XSID_AND_ATTRIBUTES_HASH>(*(data.RestrictedSidHash), SidAndAttributesMeaningDefault);

		for(DWORD i = 0; i < data.Privileges->PrivilegeCount; i++)
			Privileges.push_back(XLUID_AND_ATTRIBUTES(data.Privileges->Privileges[i]));

		AuthenticationId = std::make_shared<XLUID>(data.AuthenticationId);

		Type = static_cast<BYTE>(data.TokenType);
		ImpersonationLevel = data.ImpersonationLevel;
		MandatoryPolicy = std::make_shared<XBITSET<32>>(data.MandatoryPolicy.Policy, DwordMeaningMandatoryPolicy);
		AppContainerNumber = data.AppContainerNumber;

		Flags = std::make_shared<XBITSET<32>>(data.Flags, DwordMeaningEmpty); // Should be set to 0

		if(data.PackageSid)
			PackageSid = std::make_shared<XSID>((unsigned char*)data.PackageSid);

		CapabilitiesHash = std::make_shared<XSID_AND_ATTRIBUTES_HASH>(*(data.CapabilitiesHash), SidAndAttributesMeaningDefault);

		if(data.TrustLevelSid)
			TrustLevelSid = std::make_shared<XSID>((unsigned char*)data.TrustLevelSid);
	}
	//****************************************************************************************
	XTOKEN_ACCESS_INFORMATION::XTOKEN_ACCESS_INFORMATION(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("TOKEN_ACCESS_INFORMATION: invalid input XML");
		#pragma endregion

		#pragma region SidHash
		msxml_et sidHash = xml->selectSingleNode(L"SidHash");
		if(nullptr == sidHash)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'SidHash' XML node");

		SidHash = std::make_shared<XSID_AND_ATTRIBUTES_HASH>(sidHash, SidAndAttributesMeaningDefault);
		#pragma endregion

		#pragma region RestrictedSidHash
		msxml_et restrictedSidHash = xml->selectSingleNode(L"RestrictedSidHash");
		if(nullptr == restrictedSidHash)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'RestrictedSidHash' XML node");

		RestrictedSidHash = std::make_shared<XSID_AND_ATTRIBUTES_HASH>(restrictedSidHash, SidAndAttributesMeaningDefault);
		#pragma endregion

		#pragma region Privileges
		msxml_nt privileges = xml->selectNodes(L"Privileges/Privilege");
		if(nullptr == privileges)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'Privileges' XML node");

		for(long i = 0; i < privileges->length; i++)
			Privileges.push_back(XLUID_AND_ATTRIBUTES(privileges->item[i]));
		#pragma endregion

		#pragma region AuthenticationId

		msxml_et authenticationId = xml->selectSingleNode(L"AuthenticationId");
		if(nullptr == authenticationId)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'AuthenticationId' XML node");

		AuthenticationId = std::make_shared<XLUID>(authenticationId);
		#pragma endregion

		#pragma region Type
		msxml_et type = xml->selectSingleNode(L"Type");
		if(nullptr == type)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'Type' XML node");

		Type = _variant_t(type->text);
		#pragma endregion

		#pragma region ImpersonationLevel
		msxml_et impersonationLevel = xml->selectSingleNode(L"ImpersonationLevel");
		if(nullptr == impersonationLevel)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'ImpersonationLevel' XML node");

		ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)_variant_t(impersonationLevel->text).operator BYTE();
		#pragma endregion

		#pragma region MandatoryPolicy
		msxml_et mandatoryPolicy = xml->selectSingleNode(L"MandatoryPolicy");
		if(nullptr == mandatoryPolicy)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'MandatoryPolicy' XML node");

		MandatoryPolicy = std::make_shared<XBITSET<32>>(mandatoryPolicy, DwordMeaningMandatoryPolicy);
		#pragma endregion

		#pragma region Flags
		msxml_et flags = xml->selectSingleNode(L"Flags");
		if(nullptr == flags)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'MandatoryPolicy' XML node");

		Flags = std::make_shared<XBITSET<32>>(flags, DwordMeaningEmpty);
		#pragma endregion

		#pragma region AppContainerNumber
		msxml_et appContainerNumber = xml->selectSingleNode(L"AppContainerNumber");
		if(nullptr == appContainerNumber)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'AppContainerNumber' XML node");

		AppContainerNumber = _variant_t(appContainerNumber->text);
		#pragma endregion

		#pragma region PackageSid
		msxml_et packageSid = xml->selectSingleNode(L"PackageSid");
		if(nullptr != packageSid)
			PackageSid = std::make_shared<XSID>(packageSid);
		#pragma endregion

		#pragma region CapabilitiesHash
		msxml_et capabilitiesHash = xml->selectSingleNode(L"CapabilitiesHash");
		if(nullptr == capabilitiesHash)
			throw std::exception("TOKEN_ACCESS_INFORMATION: cannot find 'CapabilitiesHash' XML node");

		CapabilitiesHash = std::make_shared<XSID_AND_ATTRIBUTES_HASH>(capabilitiesHash, SidAndAttributesMeaningDefault);
		#pragma endregion

		#pragma region TrustLevelSid
		msxml_et trustLevelSid = xml->selectSingleNode(L"TrustLevelSid");
		if(nullptr != trustLevelSid)
			TrustLevelSid = std::make_shared<XSID>(trustLevelSid);
		#pragma endregion
	}
	//****************************************************************************************
	XTOKEN_ACCESS_INFORMATION::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("TOKEN_ACCESS_INFORMATION: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et tokeAccessInformation = xml->createElement(std::wstring(root.value_or(L"TokeAccessInformation")).c_str());
			if(nullptr == tokeAccessInformation)
				throw std::exception("TOKEN_ACCESS_INFORMATION: cannot create root XML node");
			#pragma endregion

			#pragma region SidHash
			if(nullptr == SidHash)
				throw std::exception("TOKEN_ACCESS_INFORMATION: initialize data first");

			tokeAccessInformation->appendChild(((xml_t)*SidHash)(xml, L"SidHash"));
			#pragma endregion

			#pragma region RestrictedSidHash
			if(nullptr == RestrictedSidHash)
				throw std::exception("TOKEN_ACCESS_INFORMATION: initialize data first");

			tokeAccessInformation->appendChild(((xml_t)*RestrictedSidHash)(xml, L"RestrictedSidHash"));
			#pragma endregion

			#pragma region Privileges
			msxml_et privileges = xml->createElement(L"Privileges");
			if(nullptr == privileges)
				throw std::exception("TOKEN_ACCESS_INFORMATION: cannot create 'Privileges' XML node");

			for(auto&& element : Privileges)
				privileges->appendChild(((xml_t)element)(xml, L"Privilege"));

			tokeAccessInformation->appendChild(privileges);
			#pragma endregion

			#pragma region AuthenticationId
			if(nullptr == AuthenticationId)
				throw std::exception("TOKEN_ACCESS_INFORMATION: initialize data first");

			tokeAccessInformation->appendChild(((xml_t)*AuthenticationId)(xml, L"AuthenticationId"));
			#pragma endregion

			#pragma region Type
			msxml_et type = xml->createElement(L"Type");
			if(nullptr == type)
				throw std::exception("TOKEN_ACCESS_INFORMATION: cannot create 'Type' XML node");

			type->appendChild(xml->createTextNode(_variant_t(Type).operator _bstr_t()));

			tokeAccessInformation->appendChild(type);
			#pragma endregion

			#pragma region ImpersonationLevel
			msxml_et impersonationLevel = xml->createElement(L"ImpersonationLevel");
			if(nullptr == impersonationLevel)
				throw std::exception("TOKEN_ACCESS_INFORMATION: cannot create 'ImpersonationLevel' XML node");

			impersonationLevel->appendChild(xml->createTextNode(_variant_t(ImpersonationLevel).operator _bstr_t()));

			tokeAccessInformation->appendChild(impersonationLevel);
			#pragma endregion

			#pragma region MandatoryPolicy
			tokeAccessInformation->appendChild(((xml_t)*MandatoryPolicy)(xml, L"MandatoryPolicy"));
			#pragma endregion

			#pragma region Flags
			tokeAccessInformation->appendChild(((xml_t)*Flags)(xml, L"Flags"));
			#pragma endregion

			#pragma region AppContainerNumber
			msxml_et appContainerNumber = xml->createElement(L"AppContainerNumber");
			if(nullptr == appContainerNumber)
				throw std::exception("TOKEN_ACCESS_INFORMATION: cannot create 'AppContainerNumber' XML node");

			appContainerNumber->appendChild(xml->createTextNode(_variant_t(AppContainerNumber).operator _bstr_t()));

			tokeAccessInformation->appendChild(appContainerNumber);
			#pragma endregion

			#pragma region PackageSid
			if(nullptr != PackageSid)
				tokeAccessInformation->appendChild(((xml_t)*PackageSid)(xml, L"PackageSid"));
			#pragma endregion

			#pragma region CapabilitiesHash
			if(nullptr == CapabilitiesHash)
				throw std::exception("TOKEN_ACCESS_INFORMATION: initialize data first");

			tokeAccessInformation->appendChild(((xml_t)*CapabilitiesHash)(xml, L"CapabilitiesHash"));
			#pragma endregion

			#pragma region TrustLevelSid
			if(nullptr != TrustLevelSid)
				tokeAccessInformation->appendChild(((xml_t)*TrustLevelSid)(xml, L"CapabilitiesHash"));
			#pragma endregion

			return tokeAccessInformation;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with TOKEN_SOURCE structure
	//****************************************************************************************
	struct XTOKEN_SOURCE
	{
		XTOKEN_SOURCE() = delete;
		~XTOKEN_SOURCE() = default;

		XTOKEN_SOURCE(const std::string&, const XLUID&);

		XTOKEN_SOURCE(const TOKEN_SOURCE&);
		XTOKEN_SOURCE(const msxml_et&);

		explicit operator TOKEN_SOURCE() const;
		explicit operator xml_t() const;

		std::string SourceName;
		std::shared_ptr<XLUID> Luid;
	};
	//****************************************************************************************
	XTOKEN_SOURCE::XTOKEN_SOURCE(const std::string& sourceName, const XLUID& luid)
	{
		SourceName = sourceName;
		Luid = std::make_shared<XLUID>(luid);
	}
	//****************************************************************************************
	XTOKEN_SOURCE::XTOKEN_SOURCE(const TOKEN_SOURCE& data)
	{
		SourceName = data.SourceName;
		Luid = std::make_shared<XLUID>(data.SourceIdentifier);
	}
	//****************************************************************************************
	XTOKEN_SOURCE::XTOKEN_SOURCE(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("TOKEN_SOURCE: invalid input XML");
		#pragma endregion

		#pragma region SourceName
		msxml_et sourceName = xml->selectSingleNode(L"SourceName");
		if(nullptr == sourceName)
			throw std::exception("TOKEN_SOURCE: cannot find 'SourceName' XML node");

		SourceName = (char*)sourceName->text;
		#pragma endregion

		#pragma region Luid
		msxml_et luid = xml->selectSingleNode(L"LUID");
		if(nullptr == luid)
			throw std::exception("TOKEN_SOURCE: cannot find 'LUID' XML node");

		Luid = std::make_shared<XLUID>(luid);
		#pragma endregion
	}
	//****************************************************************************************
	XTOKEN_SOURCE::operator TOKEN_SOURCE() const
	{
		TOKEN_SOURCE result{};

		sprintf_s(result.SourceName, TOKEN_SOURCE_LENGTH, SourceName.c_str());
		result.SourceIdentifier = (LUID)*Luid;

		return result;
	}
	//****************************************************************************************
	XTOKEN_SOURCE::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("TOKEN_SOURCE: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et ts = xml->createElement(std::wstring(root.value_or(L"TOKEN_SOURCE")).c_str());
			if(nullptr == ts)
				throw std::exception("TOKEN_SOURCE: cannot create root XML node");
			#pragma endregion

			#pragma region SourceName
			msxml_et sourceName = xml->createElement(L"SourceName");
			if(nullptr == sourceName)
				throw std::exception("TOKEN_SOURCE: cannot create 'SourceName' XML node");

			sourceName->appendChild(xml->createTextNode(SourceName.c_str()));

			ts->appendChild(sourceName);
			#pragma endregion

			#pragma region Luid
			if(nullptr == Luid)
				throw std::exception("TOKEN_SOURCE: initialize data first");

			ts->appendChild(((xml_t)*Luid)(xml, L"LUID"));
			#pragma endregion

			return ts;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with TOKEN_STATISTICS structure
	//****************************************************************************************
	struct XTOKEN_STATISTICS
	{
		XTOKEN_STATISTICS() = delete;
		~XTOKEN_STATISTICS() = default;

		XTOKEN_STATISTICS(
			const XLUID&,
			const XLUID&,
			const __int64&,
			const TOKEN_TYPE&,
			const SECURITY_IMPERSONATION_LEVEL&,
			const DWORD&,
			const DWORD&,
			const DWORD&,
			const DWORD&,
			const XLUID&
		);

		XTOKEN_STATISTICS(const TOKEN_STATISTICS&);
		XTOKEN_STATISTICS(const msxml_et&);

		explicit operator xml_t() const;

		std::shared_ptr<XLUID> TokenId;
		std::shared_ptr<XLUID> AuthenticationId; // Logon session LUID
		__int64 ExpirationTime = 0;
		TOKEN_TYPE TokenType = TokenPrimary;
		SECURITY_IMPERSONATION_LEVEL ImpersonationLevel = SecurityAnonymous;
		DWORD DynamicCharged = 0;   // Specifies how many bytes the system has reserved in the token for storing the default settings for new objects (the default owner and primary group SIDs and the default DACL)
		DWORD DynamicAvailable = 0; // Specifies how many of these bytes are free, with the majority of the space being occupied by the default DACL
		DWORD GroupCount = 0;
		DWORD PrivilegeCount = 0;
		std::shared_ptr<XLUID> ModifiedId;
	};
	//****************************************************************************************
	XTOKEN_STATISTICS::XTOKEN_STATISTICS(
		const XLUID& tokenId,
		const XLUID& authenticationId,
		const __int64& expirationTime,
		const TOKEN_TYPE& tokenType,
		const SECURITY_IMPERSONATION_LEVEL& impersonationLevel,
		const DWORD& dynamicCharged,
		const DWORD& dynamicAvailable,
		const DWORD& groupCount,
		const DWORD& privilegeCount,
		const XLUID& modifiedId
	)
	{
		TokenId = std::make_shared<XLUID>(tokenId);
		AuthenticationId = std::make_shared<XLUID>(authenticationId);
		ExpirationTime = expirationTime;
		TokenType = tokenType;
		ImpersonationLevel = impersonationLevel;
		DynamicCharged = dynamicCharged;
		DynamicAvailable = dynamicAvailable;
		GroupCount = groupCount;
		PrivilegeCount = privilegeCount;
		ModifiedId = std::make_shared<XLUID>(modifiedId);
	}
	//****************************************************************************************
	XTOKEN_STATISTICS::XTOKEN_STATISTICS(const TOKEN_STATISTICS& data)
	{
		TokenId = std::make_shared<XLUID>(data.TokenId);
		AuthenticationId = std::make_shared<XLUID>(data.AuthenticationId);
		ModifiedId = std::make_shared<XLUID>(data.ModifiedId);

		memcpy(&ExpirationTime, &(data.ExpirationTime), sizeof(__int64));

		TokenType = data.TokenType;
		ImpersonationLevel = data.ImpersonationLevel;
		DynamicCharged = data.DynamicCharged;
		DynamicAvailable = data.DynamicAvailable;
		GroupCount = data.GroupCount;
		PrivilegeCount = data.PrivilegeCount;
	}
	//****************************************************************************************
	XTOKEN_STATISTICS::XTOKEN_STATISTICS(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("TOKEN_STATISTICS: invalid input XML");
		#pragma endregion

		#pragma region TokenId
		msxml_et tokenId = xml->selectSingleNode(L"TokenId");
		if(nullptr == tokenId)
			throw std::exception("TOKEN_STATISTICS: cannot find 'TokenId' XML node");

		TokenId = std::make_shared<XLUID>(tokenId);
		#pragma endregion

		#pragma region AuthenticationId
		msxml_et authenticationId = xml->selectSingleNode(L"AuthenticationId");
		if(nullptr == authenticationId)
			throw std::exception("TOKEN_STATISTICS: cannot find 'AuthenticationId' XML node");

		AuthenticationId = std::make_shared<XLUID>(authenticationId);
		#pragma endregion

		#pragma region ExpirationTime
		msxml_et expirationTime = xml->selectSingleNode(L"ExpirationTime");
		if(nullptr == expirationTime)
			throw std::exception("TOKEN_STATISTICS: cannot find 'ExpirationTime' XML node");

		ExpirationTime = _variant_t(expirationTime->text);
		#pragma endregion

		#pragma region TokenType
		msxml_et tokenType = xml->selectSingleNode(L"TokenType");
		if(nullptr == tokenType)
			throw std::exception("TOKEN_STATISTICS: cannot find 'TokenType' XML node");

		TokenType = (TOKEN_TYPE)_variant_t(tokenType->text).operator BYTE();
		#pragma endregion

		#pragma region ImpersonationLevel
		msxml_et impersonationLevel = xml->selectSingleNode(L"ImpersonationLevel");
		if(nullptr == impersonationLevel)
			throw std::exception("TOKEN_STATISTICS: cannot find 'ImpersonationLevel' XML node");

		ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)_variant_t(impersonationLevel->text).operator BYTE();
		#pragma endregion

		#pragma region DynamicCharged
		msxml_et dynamicCharged = xml->selectSingleNode(L"DynamicCharged");
		if(nullptr == dynamicCharged)
			throw std::exception("TOKEN_STATISTICS: cannot find 'DynamicCharged' XML node");

		DynamicCharged = _variant_t(dynamicCharged->text);
		#pragma endregion

		#pragma region DynamicAvailable
		msxml_et dynamicAvailable = xml->selectSingleNode(L"DynamicAvailable");
		if(nullptr == dynamicAvailable)
			throw std::exception("TOKEN_STATISTICS: cannot find 'DynamicAvailable' XML node");

		DynamicAvailable = _variant_t(dynamicAvailable->text);
		#pragma endregion

		#pragma region GroupCount
		msxml_et groupCount = xml->selectSingleNode(L"GroupCount");
		if(nullptr == groupCount)
			throw std::exception("TOKEN_STATISTICS: cannot find 'GroupCount' XML node");

		GroupCount = _variant_t(groupCount->text);
		#pragma endregion

		#pragma region PrivilegeCount
		msxml_et privilegeCount = xml->selectSingleNode(L"PrivilegeCount");
		if(nullptr == privilegeCount)
			throw std::exception("TOKEN_STATISTICS: cannot find 'GroupCount' XML node");

		PrivilegeCount = _variant_t(privilegeCount->text);
		#pragma endregion

		#pragma region ModifiedId
		msxml_et modifiedId = xml->selectSingleNode(L"ModifiedId");
		if(nullptr == modifiedId)
			throw std::exception("TOKEN_STATISTICS: cannot find 'ModifiedId' XML node");

		ModifiedId = std::make_shared<XLUID>(modifiedId);
		#pragma endregion
	}
	//****************************************************************************************
	XTOKEN_STATISTICS::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("TOKEN_STATISTICS: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et ts = xml->createElement(std::wstring(root.value_or(L"TOKEN_STATISTICS")).c_str());
			if(nullptr == ts)
				throw std::exception("TOKEN_STATISTICS: cannot create root XML node");
			#pragma endregion

			#pragma region TokenId
			if(nullptr == TokenId)
				throw std::exception("TOKEN_STATISTICS: initialize data first");

			ts->appendChild(((xml_t)*TokenId)(xml, L"TokenId"));
			#pragma endregion

			#pragma region AuthenticationId
			if(nullptr == AuthenticationId)
				throw std::exception("TOKEN_STATISTICS: initialize data first");

			ts->appendChild(((xml_t)*AuthenticationId)(xml, L"AuthenticationId"));
			#pragma endregion

			#pragma region ExpirationTime
			msxml_et expirationTime = xml->createElement(L"ExpirationTime");
			if(nullptr == expirationTime)
				return nullptr;

			expirationTime->appendChild(xml->createTextNode(_variant_t(ExpirationTime).operator _bstr_t()));

			ts->appendChild(expirationTime);
			#pragma endregion

			#pragma region TokenType
			msxml_et tokenType = xml->createElement(L"TokenType");
			if(nullptr == tokenType)
				throw std::exception("TOKEN_STATISTICS: cannot create 'TokenType' XML node");

			tokenType->appendChild(xml->createTextNode(_variant_t(TokenType).operator _bstr_t()));

			ts->appendChild(tokenType);
			#pragma endregion

			#pragma region ImpersonationLevel
			msxml_et impersonationLevel = xml->createElement(L"ImpersonationLevel");
			if(nullptr == impersonationLevel)
				throw std::exception("TOKEN_STATISTICS: cannot create 'ImpersonationLevel' XML node");

			impersonationLevel->appendChild(xml->createTextNode(_variant_t(ImpersonationLevel).operator _bstr_t()));

			ts->appendChild(impersonationLevel);
			#pragma endregion

			#pragma region DynamicCharged
			msxml_et dynamicCharged = xml->createElement(L"DynamicCharged");
			if(nullptr == dynamicCharged)
				throw std::exception("TOKEN_STATISTICS: cannot create 'ImpersonationLevel' XML node");

			dynamicCharged->appendChild(xml->createTextNode(_variant_t(DynamicCharged).operator _bstr_t()));

			ts->appendChild(dynamicCharged);
			#pragma endregion

			#pragma region DynamicAvailable
			msxml_et dynamicAvailable = xml->createElement(L"DynamicAvailable");
			if(nullptr == dynamicAvailable)
				throw std::exception("TOKEN_STATISTICS: cannot create 'DynamicAvailable' XML node");

			dynamicAvailable->appendChild(xml->createTextNode(_variant_t(DynamicAvailable).operator _bstr_t()));

			ts->appendChild(dynamicAvailable);
			#pragma endregion

			#pragma region GroupCount
			msxml_et groupCount = xml->createElement(L"GroupCount");
			if(nullptr == groupCount)
				throw std::exception("TOKEN_STATISTICS: cannot create 'GroupCount' XML node");

			groupCount->appendChild(xml->createTextNode(_variant_t(GroupCount).operator _bstr_t()));

			ts->appendChild(groupCount);
			#pragma endregion

			#pragma region PrivilegeCount
			msxml_et privilegeCount = xml->createElement(L"PrivilegeCount");
			if(nullptr == privilegeCount)
				throw std::exception("TOKEN_STATISTICS: cannot create 'PrivilegeCount' XML node");

			privilegeCount->appendChild(xml->createTextNode(_variant_t(PrivilegeCount).operator _bstr_t()));

			ts->appendChild(privilegeCount);
			#pragma endregion

			#pragma region ModifiedId
			if(nullptr == ModifiedId)
				throw std::exception("TOKEN_STATISTICS: initialize data first");

			ts->appendChild(((xml_t)*ModifiedId)(xml, L"ModifiedId"));
			#pragma endregion

			return ts;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Additional definitions
	//****************************************************************************************
	struct CREATE_PARAMETERS
	{
		DWORD DesiredAccess = TOKEN_ALL_ACCESS;

		// SYSTEM_LUID =              { 0x3e7, 0 } // working in create token
		// ANONYMOUS_LOGON_LUID =     { 0x3e6, 0 } // working in create token
		// LOCALSERVICE_LUID =        { 0x3e5, 0 } // working in create token
		// NETWORKSERVICE_LUID =      { 0x3e4, 0 } // working in create token
		// IUSER_LUID =               { 0x3e3, 0 } // NOT working in create token
		// PROTECTED_TO_SYSTEM_LUID = { 0x3e2, 0 } // NOT working in create token
		LUID AuthenticationId = { 0, 0 };
	};

	template<typename T> bool check_pointer(T) { return false; }
	template<typename T> bool check_pointer(T* value) { return (nullptr == value); }

	typedef enum _FUNC_VARIANT
	{
		VariantIntegral = 1,
		VariantPointer,
		VariantVector
	} FUNC_VARIANT, * PFUNC_VARIANT;

	template<FUNC_VARIANT T> struct is_variant_integral{};
	template<> struct is_variant_integral<VariantIntegral> { using type = FUNC_VARIANT; };

	template<FUNC_VARIANT T> struct is_variant_pointer {};
	template<> struct is_variant_pointer<VariantPointer> { using type = FUNC_VARIANT; };

	template<FUNC_VARIANT T> struct is_variant_vector {};
	template<> struct is_variant_vector<VariantVector> { using type = FUNC_VARIANT; };

	template<typename T> struct is_nullptr {};
	template<> struct is_nullptr<std::nullptr_t> { using type = bool; };

	template<typename T> struct is_not_nullptr { using type = bool; };
	template<> struct is_not_nullptr<std::nullptr_t> {};

	template<TOKEN_INFORMATION_CLASS variant> struct token_info;

	template<> struct token_info<TokenUser> 
	{
		using type = XSID_AND_ATTRIBUTES;
		using raw = TOKEN_USER;
		using cast = SID_AND_ATTRIBUTES;
		static constexpr SID_AND_ATTRIBUTES TOKEN_USER::* member = &TOKEN_USER::User;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenOwner>
	{
		using type = XSID;
		using raw = TOKEN_OWNER;
		using cast = unsigned char*;
		static constexpr PSID TOKEN_OWNER::* member = &TOKEN_OWNER::Owner;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenGroups>
	{
		using type = XSID_AND_ATTRIBUTES;
		using raw = TOKEN_GROUPS;
		using cast = SID_AND_ATTRIBUTES;
		static constexpr SID_AND_ATTRIBUTES (TOKEN_GROUPS::* member)[ANYSIZE_ARRAY] = &TOKEN_GROUPS::Groups;
		static constexpr FUNC_VARIANT variant = VariantVector;

		using count_type = DWORD;
		static constexpr DWORD TOKEN_GROUPS::* count = &TOKEN_GROUPS::GroupCount;
	};

	template<> struct token_info<TokenPrivileges>
	{
		using type = XLUID_AND_ATTRIBUTES;
		using raw = TOKEN_PRIVILEGES;
		using cast = LUID_AND_ATTRIBUTES;
		static constexpr LUID_AND_ATTRIBUTES (TOKEN_PRIVILEGES::* member)[ANYSIZE_ARRAY] = &TOKEN_PRIVILEGES::Privileges;
		static constexpr FUNC_VARIANT variant = VariantVector;

		using count_type = DWORD;
		static constexpr DWORD TOKEN_PRIVILEGES::* count = &TOKEN_PRIVILEGES::PrivilegeCount;
	};

	template<> struct token_info<TokenSessionId>
	{ 
		using type = DWORD; 
		using raw = DWORD;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenPrimaryGroup>
	{
		using type = XSID;
		using raw = TOKEN_PRIMARY_GROUP;
		using cast = unsigned char*;
		static constexpr PSID TOKEN_PRIMARY_GROUP::* member = &TOKEN_PRIMARY_GROUP::PrimaryGroup;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenDefaultDacl>
	{
		using type = XACL;
		using raw = TOKEN_DEFAULT_DACL;
		using cast = unsigned char*;
		static constexpr PACL TOKEN_DEFAULT_DACL::* member = &TOKEN_DEFAULT_DACL::DefaultDacl;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenSource>
	{
		using type = XTOKEN_SOURCE;
		using raw = TOKEN_SOURCE;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenType>
	{
		using type = BYTE;
		using raw = TOKEN_TYPE;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenImpersonationLevel>
	{
		using type = SECURITY_IMPERSONATION_LEVEL;
		using raw = SECURITY_IMPERSONATION_LEVEL;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenStatistics>
	{
		using type = XTOKEN_STATISTICS;
		using raw = TOKEN_STATISTICS;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenRestrictedSids>
	{
		using type = XSID_AND_ATTRIBUTES;
		using raw = TOKEN_GROUPS;
		using cast = SID_AND_ATTRIBUTES;
		static constexpr SID_AND_ATTRIBUTES (TOKEN_GROUPS::* member)[ANYSIZE_ARRAY] = &TOKEN_GROUPS::Groups;
		static constexpr FUNC_VARIANT variant = VariantVector;

		using count_type = DWORD;
		static constexpr DWORD TOKEN_GROUPS::* count = &TOKEN_GROUPS::GroupCount;
	};

	template<> struct token_info<TokenGroupsAndPrivileges>
	{
		using type = XTOKEN_GROUPS_AND_PRIVILEGES;
		using raw = TOKEN_GROUPS_AND_PRIVILEGES;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenSandBoxInert>
	{
		using type = DWORD;
		using raw = DWORD;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenOrigin>
	{
		using type = XLUID;
		using raw = TOKEN_ORIGIN;
		using cast = LUID;
		static constexpr LUID TOKEN_ORIGIN::* member = &TOKEN_ORIGIN::OriginatingLogonSession;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenElevationType>
	{
		using type = TOKEN_ELEVATION_TYPE;
		using raw = TOKEN_ELEVATION_TYPE;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	struct XTOKEN;
	template<> struct token_info<TokenLinkedToken>
	{
		using type = XTOKEN;
		using raw = TOKEN_LINKED_TOKEN;
		using cast = HANDLE;
		static constexpr HANDLE TOKEN_LINKED_TOKEN::* member = &TOKEN_LINKED_TOKEN::LinkedToken;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenElevation>
	{
		using type = DWORD;
		using raw = TOKEN_ELEVATION;
		using cast = bool;
		static constexpr DWORD TOKEN_ELEVATION::* member = &TOKEN_ELEVATION::TokenIsElevated;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenHasRestrictions>
	{
		using type = DWORD;
		using raw = DWORD;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenAccessInformation>
	{
		using type = XTOKEN_ACCESS_INFORMATION;
		using raw = TOKEN_ACCESS_INFORMATION;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenVirtualizationAllowed>
	{
		using type = DWORD;
		using raw = DWORD;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenVirtualizationEnabled>
	{
		using type = DWORD;
		using raw = DWORD;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenIntegrityLevel>
	{
		using type = XSID_AND_ATTRIBUTES;
		using raw = TOKEN_MANDATORY_LABEL;
		using cast = SID_AND_ATTRIBUTES;
		static constexpr SID_AND_ATTRIBUTES TOKEN_MANDATORY_LABEL::* member = &TOKEN_MANDATORY_LABEL::Label;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenUIAccess>
	{
		using type = DWORD;
		using raw = DWORD;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenMandatoryPolicy>
	{
		using type = XBITSET<32>;
		using raw = TOKEN_MANDATORY_POLICY;
		using cast = DWORD;
		static constexpr DWORD TOKEN_MANDATORY_POLICY::* member = &TOKEN_MANDATORY_POLICY::Policy;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenLogonSid>
	{
		using type = XSID_AND_ATTRIBUTES;
		using raw = TOKEN_GROUPS;
		using cast = SID_AND_ATTRIBUTES;
		static constexpr SID_AND_ATTRIBUTES(TOKEN_GROUPS::* member)[ANYSIZE_ARRAY] = &TOKEN_GROUPS::Groups;
		static constexpr FUNC_VARIANT variant = VariantVector;

		using count_type = DWORD;
		static constexpr DWORD TOKEN_GROUPS::* count = &TOKEN_GROUPS::GroupCount;
	};

	template<> struct token_info<TokenIsAppContainer>
	{
		using type = DWORD;
		using raw = DWORD;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenCapabilities>
	{
		using type = XSID_AND_ATTRIBUTES;
		using raw = TOKEN_GROUPS;
		using cast = SID_AND_ATTRIBUTES;
		static constexpr SID_AND_ATTRIBUTES(TOKEN_GROUPS::* member)[ANYSIZE_ARRAY] = &TOKEN_GROUPS::Groups;
		static constexpr FUNC_VARIANT variant = VariantVector;

		using count_type = DWORD;
		static constexpr DWORD TOKEN_GROUPS::* count = &TOKEN_GROUPS::GroupCount;
	};

	template<> struct token_info<TokenAppContainerSid>
	{
		using type = XSID;
		using raw = TOKEN_APPCONTAINER_INFORMATION;
		using cast = unsigned char*;
		static constexpr PSID TOKEN_APPCONTAINER_INFORMATION::* member = &TOKEN_APPCONTAINER_INFORMATION::TokenAppContainer;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenAppContainerNumber>
	{
		using type = DWORD;
		using raw = DWORD;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantIntegral;
	};

	template<> struct token_info<TokenUserClaimAttributes>
	{
		using type = XSECURITY_ATTRIBUTES_INFORMATION;
		using raw = CLAIM_SECURITY_ATTRIBUTES_INFORMATION;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenDeviceClaimAttributes>
	{
		using type = XSECURITY_ATTRIBUTES_INFORMATION;
		using raw = CLAIM_SECURITY_ATTRIBUTES_INFORMATION;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenDeviceGroups>
	{
		using type = XSID_AND_ATTRIBUTES;
		using raw = TOKEN_GROUPS;
		using cast = SID_AND_ATTRIBUTES;
		static constexpr SID_AND_ATTRIBUTES(TOKEN_GROUPS::* member)[ANYSIZE_ARRAY] = &TOKEN_GROUPS::Groups;
		static constexpr FUNC_VARIANT variant = VariantVector;

		using count_type = DWORD;
		static constexpr DWORD TOKEN_GROUPS::* count = &TOKEN_GROUPS::GroupCount;
	};

	template<> struct token_info<TokenRestrictedDeviceGroups>
	{
		using type = XSID_AND_ATTRIBUTES;
		using raw = TOKEN_GROUPS;
		using cast = SID_AND_ATTRIBUTES;
		static constexpr SID_AND_ATTRIBUTES(TOKEN_GROUPS::* member)[ANYSIZE_ARRAY] = &TOKEN_GROUPS::Groups;
		static constexpr FUNC_VARIANT variant = VariantVector;

		using count_type = DWORD;
		static constexpr DWORD TOKEN_GROUPS::* count = &TOKEN_GROUPS::GroupCount;
	};

	template<> struct token_info<TokenSecurityAttributes>
	{
		using type = XSECURITY_ATTRIBUTES_INFORMATION;
		using raw = TOKEN_SECURITY_ATTRIBUTES_INFORMATION;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<> struct token_info<TokenSingletonAttributes>
	{
		using type = XSECURITY_ATTRIBUTES_INFORMATION;
		using raw = TOKEN_SECURITY_ATTRIBUTES_INFORMATION;
		using cast = std::nullptr_t;
		static constexpr FUNC_VARIANT variant = VariantPointer;
	};

	template<TOKEN_INFORMATION_CLASS variant, typename is_nullptr<typename token_info<variant>::cast>::type = true>
	typename token_info<variant>::type get_result(const typename token_info<variant>::raw& result)
	{
		return (typename token_info<variant>::type)result;
	}

	template<TOKEN_INFORMATION_CLASS variant, typename is_not_nullptr<typename token_info<variant>::cast>::type = false>
	typename token_info<variant>::type get_result(const typename token_info<variant>::raw& result)
	{
		return (typename token_info<variant>::type)(std::invoke(token_info<variant>::member, result));
	}

	template<TOKEN_INFORMATION_CLASS variant, typename is_nullptr<typename token_info<variant>::cast>::type = true>
	typename token_info<variant>::raw get_element(typename token_info<variant>::raw* buffer)
	{
		return *buffer;
	}

	template<TOKEN_INFORMATION_CLASS variant, typename is_nullptr<typename token_info<variant>::cast>::type = true>
	typename token_info<variant>::raw get_element(typename token_info<variant>::raw* buffer, typename token_info<variant>::count_type i)
	{
		return buffer[i];
	}

	template<TOKEN_INFORMATION_CLASS variant, typename is_not_nullptr<typename token_info<variant>::cast>::type = false>
	typename token_info<variant>::cast get_element(typename token_info<variant>::raw* buffer)
	{
		return (typename token_info<variant>::cast)(std::invoke(token_info<variant>::member, buffer));
	}

	template<TOKEN_INFORMATION_CLASS variant, typename is_not_nullptr<typename token_info<variant>::cast>::type = false>
	typename token_info<variant>::cast get_element(typename token_info<variant>::raw* buffer, typename token_info<variant>::count_type i)
	{
		return (typename token_info<variant>::cast)(std::invoke(token_info<variant>::member, buffer)[i]);
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Major class for working with security tokens
	//****************************************************************************************
	struct XTOKEN
	{
		XTOKEN() = delete;
		~XTOKEN() = default;

		XTOKEN(const HANDLE, bool = false);
		XTOKEN(const msxml_et&);

		explicit operator xml_t() const;
		explicit operator HANDLE() const;

		template<TOKEN_INFORMATION_CLASS variant, typename is_variant_integral<token_info<variant>::variant>::type = VariantIntegral>
		static typename token_info<variant>::type GetTokenInfo(const HANDLE token);

		template<TOKEN_INFORMATION_CLASS variant, typename... Types, typename is_variant_pointer<token_info<variant>::variant>::type = VariantPointer>
		static std::shared_ptr<typename token_info<variant>::type> GetTokenInfo(const HANDLE token, Types&&... args);

		template<TOKEN_INFORMATION_CLASS variant, typename... Types, typename is_variant_vector<token_info<variant>::variant>::type = VariantVector>
		static std::vector<typename token_info<variant>::type> GetTokenInfo(const HANDLE token, Types&&... args);

		static BOOL ChangePrivileges(const HANDLE, const std::vector<XLUID>&, const DWORD& = SE_PRIVILEGE_ENABLED);
		static BOOL ChangePrivileges(const std::vector<std::wstring>&, const HANDLE, const DWORD& = SE_PRIVILEGE_ENABLED);

		static HANDLE Create(
			const XSID_AND_ATTRIBUTES& /*user*/,
			const XSID& /*primaryGroup*/ = XSID::Everyone,
			const std::vector<XLUID_AND_ATTRIBUTES>& /*privileges*/ = {},
			const std::vector<XSID_AND_ATTRIBUTES>& /*groups*/ = {},
			const std::optional<XSD>& /*securityDescriptor*/ = std::nullopt,
			const std::optional<XSECURITY_ATTRIBUTES_INFORMATION>& /*userClaimAttributes*/ = std::nullopt,
			const std::optional<XSECURITY_ATTRIBUTES_INFORMATION>& /*deviceClaimAttributes*/ = std::nullopt,
			const std::optional<XSECURITY_ATTRIBUTES_INFORMATION>& /*securityAttributes*/ = std::nullopt,
			const std::vector<XSID_AND_ATTRIBUTES>& /*deviceGroups*/ = {},
			const std::optional<XBITSET<32>>& /*mandatoryPolicy*/ = std::nullopt,
			const std::optional<XACL>& /*defaultDacl*/ = std::nullopt,
			const std::optional<XTOKEN_SOURCE>& /*source*/ = std::nullopt,
			const DWORD& /*desiredAccess*/ = TOKEN_ALL_ACCESS,
			const std::optional<LUID>& /*authenticationId*/ = std::nullopt
		);

		#pragma region Properties
		HANDLE Token;
		bool IsLinkedToken;

		std::shared_ptr<XSD> SecurityDescriptor;

		std::shared_ptr<XSID_AND_ATTRIBUTES> User;
		std::vector<XSID_AND_ATTRIBUTES> Groups;
		std::vector<XLUID_AND_ATTRIBUTES> Privileges;
		std::shared_ptr<XSID> Owner;
		std::shared_ptr<XSID> PrimaryGroup;
		std::shared_ptr<XACL> DefaultDacl;
		std::shared_ptr<XTOKEN_SOURCE> Source;
		BYTE Type = 0;
		SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
		std::vector<XSID_AND_ATTRIBUTES> RestrictedSids;
		DWORD SessionId = 0;
		std::shared_ptr<XLUID> Origin;
		DWORD Elevation = 0;
		DWORD HasRestrictions = 0;
		TOKEN_ELEVATION_TYPE ElevationType = TokenElevationTypeDefault;
		std::shared_ptr<XSID_AND_ATTRIBUTES> IntegrityLevel;
		DWORD UIAccess = 0;
		std::vector<XSID_AND_ATTRIBUTES> LogonSid;
		std::vector<XSID_AND_ATTRIBUTES> Capabilities;
		std::vector<XSID_AND_ATTRIBUTES> DeviceGroups;
		std::vector<XSID_AND_ATTRIBUTES> RestrictedDeviceGroups;
		std::shared_ptr<XBITSET<32>> MandatoryPolicy;
		DWORD AppContainerNumber = 0;
		DWORD IsAppContainer = 0;
		DWORD SandBoxInert = 0;
		DWORD VirtualizationAllowed = 0;
		DWORD VirtualizationEnabled = 0;

		std::shared_ptr<XTOKEN> LinkedToken; // Full Token for a restricted token, could be achived only if user is in admin group

		std::shared_ptr<XSID> AppContainerSid;

		std::shared_ptr<XTOKEN_ACCESS_INFORMATION> AccessInformation;
		std::shared_ptr<XTOKEN_GROUPS_AND_PRIVILEGES> GroupsAndPrivileges;

		std::shared_ptr<XSECURITY_ATTRIBUTES_INFORMATION> SecurityAttributes;
		std::shared_ptr<XSECURITY_ATTRIBUTES_INFORMATION> SingletonAttributes;

		std::shared_ptr<XTOKEN_STATISTICS> Statistics;
		std::shared_ptr<XSECURITY_ATTRIBUTES_INFORMATION> UserClaimAttributes;
		std::shared_ptr<XSECURITY_ATTRIBUTES_INFORMATION> DeviceClaimAttributes;

		// This structure participates only in case of call to "operator HANDLE"
		CREATE_PARAMETERS CreateParameters{};
		#pragma endregion
	};
	//****************************************************************************************
	template<TOKEN_INFORMATION_CLASS variant, typename is_variant_integral<token_info<variant>::variant>::type>
	typename token_info<variant>::type XTOKEN::GetTokenInfo(const HANDLE token)
	{
		DWORD size = 0;

		if(!GetTokenInformation(token, variant, nullptr, size, &size))
		{
			DWORD error = GetLastError();
			if((ERROR_INSUFFICIENT_BUFFER != error) && (ERROR_BAD_LENGTH != error))
				return typename token_info<variant>::type{};
		}

		typename token_info<variant>::raw result{};

		if(!GetTokenInformation(token, variant, &result, size, &size))
			return typename token_info<variant>::type{};

		return get_result<variant>(result);
	};
	//****************************************************************************************
	template<TOKEN_INFORMATION_CLASS variant, typename... Types, typename is_variant_pointer<token_info<variant>::variant>::type>
	std::shared_ptr<typename token_info<variant>::type> XTOKEN::GetTokenInfo(const HANDLE token, Types&&... args)
	{
		DWORD size = 0;

		if(!GetTokenInformation(token, variant, nullptr, size, &size))
		{
			DWORD error = GetLastError();
			if((ERROR_INSUFFICIENT_BUFFER != error) && (ERROR_BAD_LENGTH != error))
				return nullptr;
		}

		std::unique_ptr<typename token_info<variant>::raw> buffer{ static_cast<typename token_info<variant>::raw*>(::operator new(size)) };

		if(!GetTokenInformation(token, variant, buffer.get(), size, &size))
			return nullptr;

		auto element = get_element<variant>(buffer.get());
		if(false == check_pointer(element))
		{
			auto result = std::make_shared<typename token_info<variant>::type>(element, std::forward<Types>(args)...);
			return result;
		}

		return nullptr;
	};
	//****************************************************************************************
	template<TOKEN_INFORMATION_CLASS variant, typename... Types, typename is_variant_vector<token_info<variant>::variant>::type>
	std::vector<typename token_info<variant>::type> XTOKEN::GetTokenInfo(const HANDLE token, Types&&... args)
	{
		DWORD size = 0;

		if(!GetTokenInformation(token, variant, nullptr, size, &size))
		{
			DWORD error = GetLastError();
			if((ERROR_INSUFFICIENT_BUFFER != error) && (ERROR_BAD_LENGTH != error))
				return std::vector<typename token_info<variant>::type>{};
		}

		std::unique_ptr<typename token_info<variant>::raw> buffer{ static_cast<typename token_info<variant>::raw*>(::operator new(size)) };

		if(!GetTokenInformation(token, variant, buffer.get(), size, &size))
			std::vector<typename token_info<variant>::type>{};

		std::vector<typename token_info<variant>::type> result;

		for(typename token_info<variant>::count_type i = 0; i < std::invoke(token_info<variant>::count, buffer.get()); i++)
		{
			auto element = get_element<variant>(buffer.get(), i);
			if(!check_pointer(element))
				result.push_back(typename token_info<variant>::type{ element, std::forward<Types>(args)... });
		}

		return result;
	};
	//****************************************************************************************
	XTOKEN::XTOKEN(const HANDLE token, bool isLinkedToken) : Token(token), IsLinkedToken(isLinkedToken)
	{
		SecurityDescriptor = std::make_shared<XSD>(XSD::GetFromKernelObject(token));

		User = XTOKEN::GetTokenInfo<TokenUser>(token);
		Groups = XTOKEN::GetTokenInfo<TokenGroups>(token);
		Privileges = XTOKEN::GetTokenInfo<TokenPrivileges>(token);
		Owner = XTOKEN::GetTokenInfo<TokenOwner>(token);
		PrimaryGroup = XTOKEN::GetTokenInfo<TokenPrimaryGroup>(token);
		DefaultDacl = XTOKEN::GetTokenInfo<TokenDefaultDacl>(token, DwordMeaningToken);
		Source = XTOKEN::GetTokenInfo<TokenSource>(token);
		Type = XTOKEN::GetTokenInfo<TokenType>(token);
		ImpersonationLevel = XTOKEN::GetTokenInfo<TokenImpersonationLevel>(token);
		Statistics = XTOKEN::GetTokenInfo<TokenStatistics>(token);
		RestrictedSids = XTOKEN::GetTokenInfo<TokenRestrictedSids>(token);
		SessionId = XTOKEN::GetTokenInfo<TokenSessionId>(token);
		GroupsAndPrivileges = XTOKEN::GetTokenInfo<TokenGroupsAndPrivileges>(token);
		// TokenSessionReference - Reserved
		SandBoxInert = XTOKEN::GetTokenInfo<TokenSandBoxInert>(token);
		// TokenAuditPolicy - Reserved
		Origin = XTOKEN::GetTokenInfo<TokenOrigin>(token);
		ElevationType = XTOKEN::GetTokenInfo<TokenElevationType>(token);
		LinkedToken = (isLinkedToken) ? nullptr : XTOKEN::GetTokenInfo<TokenLinkedToken>(token, true);
		Elevation = XTOKEN::GetTokenInfo<TokenElevation>(token);
		HasRestrictions = XTOKEN::GetTokenInfo<TokenHasRestrictions>(token);
		AccessInformation = XTOKEN::GetTokenInfo<TokenAccessInformation>(token);
		VirtualizationAllowed = XTOKEN::GetTokenInfo<TokenVirtualizationAllowed>(token);
		VirtualizationEnabled = XTOKEN::GetTokenInfo<TokenVirtualizationEnabled>(token);
		IntegrityLevel = XTOKEN::GetTokenInfo<TokenIntegrityLevel>(token);
		UIAccess = XTOKEN::GetTokenInfo<TokenUIAccess>(token);
		MandatoryPolicy = XTOKEN::GetTokenInfo<TokenMandatoryPolicy>(token, DwordMeaningMandatoryPolicy);
		LogonSid = XTOKEN::GetTokenInfo<TokenLogonSid>(token);
		IsAppContainer = XTOKEN::GetTokenInfo<TokenIsAppContainer>(token);
		Capabilities = XTOKEN::GetTokenInfo<TokenCapabilities>(token);
		AppContainerSid = XTOKEN::GetTokenInfo<TokenAppContainerSid>(token);
		AppContainerNumber = XTOKEN::GetTokenInfo<TokenAppContainerNumber>(token);
		UserClaimAttributes = XTOKEN::GetTokenInfo<TokenUserClaimAttributes>(token);
		DeviceClaimAttributes = XTOKEN::GetTokenInfo<TokenDeviceClaimAttributes>(token);
		// TokenRestrictedUserClaimAttributes - Reserved
		// TokenRestrictedDeviceClaimAttributes - Reserved
		DeviceGroups = XTOKEN::GetTokenInfo<TokenDeviceGroups>(token);
		RestrictedDeviceGroups = XTOKEN::GetTokenInfo<TokenRestrictedDeviceGroups>(token);
		SecurityAttributes = XTOKEN::GetTokenInfo<TokenSecurityAttributes>(token);
		// TokenIsRestricted - Reserved
		// TokenProcessTrustLevel - Reserved (?)
		// TokenPrivateNameSpace - Reserved (?)
		SingletonAttributes = XTOKEN::GetTokenInfo<TokenSingletonAttributes>(token);
		// TokenBnoIsolation - Reserved (?)
		// TokenChildProcessFlags - Reserved
		// TokenIsLessPrivilegedAppContainer - Reserved
		// TokenIsSandboxed - Reserved
		// TokenOriginatingProcessTrustLevel - Reserved
	}
	//****************************************************************************************
	XTOKEN::XTOKEN(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XTOKEN: invalid input XML");
		#pragma endregion

		#pragma region SecurityDescriptor
		msxml_et securityDescriptor = xml->selectSingleNode(L"SecurityDescriptor");
		if(nullptr != securityDescriptor)
			SecurityDescriptor = std::make_shared<XSD>(securityDescriptor, DwordMeaningToken);
		#pragma endregion

		#pragma region SecurityAttributes

		msxml_et securityAttributes = xml->selectSingleNode(L"SecurityAttributes");
		if(nullptr != securityAttributes)
			SecurityAttributes = std::make_shared<XSECURITY_ATTRIBUTES_INFORMATION>(securityAttributes);
		#pragma endregion

		#pragma region User
		msxml_et user = xml->selectSingleNode(L"User");
		if(nullptr == user)
			throw std::exception("XTOKEN: cannot find 'User' XML node");

		User = std::make_shared<XSID_AND_ATTRIBUTES>(user);
		#pragma endregion

		#pragma region Groups
		msxml_nt groups = xml->selectNodes(L"Groups/Group");
		if(nullptr == groups)
			throw std::exception("XTOKEN: cannot find 'Groups' XML node");

		for(int i = 0; i < groups->length; i++)
			Groups.push_back(XSID_AND_ATTRIBUTES(groups->item[i]));
		#pragma endregion

		#pragma region Privileges
		msxml_nt privileges = xml->selectNodes(L"Privileges/Privilege");
		if(nullptr == privileges)
			throw std::exception("XTOKEN: cannot find 'Privileges' XML node");

		for(int i = 0; i < privileges->length; i++)
			Privileges.push_back(XLUID_AND_ATTRIBUTES(privileges->item[i]));
		#pragma endregion

		#pragma region Owner
		msxml_et owner = xml->selectSingleNode(L"Owner");
		if(nullptr == owner)
			throw std::exception("XTOKEN: cannot find 'Owner' XML node");

		Owner = std::make_shared<XSID>(owner);
		#pragma endregion

		#pragma region AppContainerSid
		msxml_et appContainerSid = xml->selectSingleNode(L"AppContainerSid");
		if(nullptr != appContainerSid)
			AppContainerSid = std::make_shared<XSID>(appContainerSid);
		#pragma endregion

		#pragma region PrimaryGroup
		msxml_et primaryGroup = xml->selectSingleNode(L"PrimaryGroup");
		if(nullptr == primaryGroup)
			throw std::exception("XTOKEN: cannot find 'PrimaryGroup' XML node");

		PrimaryGroup = std::make_shared<XSID>(primaryGroup);
		#pragma endregion

		#pragma region DefaultDacl
		msxml_et defaultDacl = xml->selectSingleNode(L"DefaultDacl");
		if(nullptr != defaultDacl)
			DefaultDacl = std::make_shared<XACL>(defaultDacl, DwordMeaningToken);
		#pragma endregion

		#pragma region Source
		msxml_et source = xml->selectSingleNode(L"Source");
		if(nullptr != source)
			Source = std::make_shared<XTOKEN_SOURCE>(source);
		#pragma endregion

		#pragma region Type
		msxml_et type = xml->selectSingleNode(L"Type");
		if(nullptr == type)
			throw std::exception("XTOKEN: cannot find 'Type' XML node");

		Type = _variant_t(type->text);
		#pragma endregion

		#pragma region ImpersonationLevel
		msxml_et impersonationLevel = xml->selectSingleNode(L"ImpersonationLevel");
		if(nullptr == impersonationLevel)
			throw std::exception("XTOKEN: cannot find 'ImpersonationLevel' XML node");

		ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)_variant_t(impersonationLevel->text).operator BYTE();
		#pragma endregion

		#pragma region RestrictedSids
		msxml_nt restrictedSids = xml->selectNodes(L"RestrictedSids/RestrictedSid");
		if(nullptr != restrictedSids)
		{
			for(long i = 0; i < restrictedSids->length; i++)
				RestrictedSids.push_back(XSID_AND_ATTRIBUTES(restrictedSids->item[i]));
		}
		#pragma endregion

		#pragma region SessionId
		msxml_et sessionId = xml->selectSingleNode(L"SessionId");
		if(nullptr == sessionId)
			throw std::exception("XTOKEN: cannot find 'SessionId' XML node");
		
		SessionId = _variant_t(sessionId->text);
		#pragma endregion

		#pragma region Origin
		msxml_et origin = xml->selectSingleNode(L"Origin");
		if(nullptr != origin)
			Origin = std::make_shared<XLUID>(origin);
		#pragma endregion

		#pragma region Elevation
		msxml_et elevation = xml->selectSingleNode(L"Elevation");
		if(nullptr == elevation)
			throw std::exception("XTOKEN: cannot find 'Elevation' XML node");

		Elevation = _variant_t(elevation->text);
		#pragma endregion

		#pragma region HasRestrictions
		msxml_et hasRestrictions = xml->selectSingleNode(L"HasRestrictions");
		if(nullptr == hasRestrictions)
			throw std::exception("XTOKEN: cannot find 'HasRestrictions' XML node");

		HasRestrictions = _variant_t(hasRestrictions->text);
		#pragma endregion

		#pragma region ElevationType
		msxml_et elevationType = xml->selectSingleNode(L"ElevationType");
		if(nullptr == elevationType)
			throw std::exception("XTOKEN: cannot find 'ElevationType' XML node");

		ElevationType = (TOKEN_ELEVATION_TYPE)_variant_t(elevationType->text).operator BYTE();
		#pragma endregion

		#pragma region IntegrityLevel
		msxml_et integrityLevel = xml->selectSingleNode(L"IntegrityLevel");
		if(nullptr == integrityLevel)
			throw std::exception("XTOKEN: cannot find 'IntegrityLevel' XML node");

		IntegrityLevel = std::make_shared<XSID_AND_ATTRIBUTES>(integrityLevel);
		#pragma endregion

		#pragma region UIAccess
		msxml_et uiAccess = xml->selectSingleNode(L"UIAccess");
		if(nullptr == uiAccess)
			throw std::exception("XTOKEN: cannot find 'UIAccess' XML node");

		UIAccess = _variant_t(uiAccess->text);
		#pragma endregion

		#pragma region LogonSid
		msxml_nt logonSid = xml->selectNodes(L"LogonSids/LogonSid");
		if(nullptr != logonSid) // Could be a situation when token is from SYSTEM account and has no LogonSID
		{
			for(long i = 0; i < logonSid->length; i++)
				LogonSid.push_back(XSID_AND_ATTRIBUTES(logonSid->item[i]));
		}
		#pragma endregion

		#pragma region Capabilities
		msxml_nt capabilities = xml->selectNodes(L"Capabilities/Capability");
		if(nullptr != capabilities)
		{
			for(long i = 0; i < capabilities->length; i++)
				Capabilities.push_back(XSID_AND_ATTRIBUTES(capabilities->item[i]));
		}
		#pragma endregion

		#pragma region DeviceGroups
		msxml_nt deviceGroups = xml->selectNodes(L"DeviceGroups/DeviceGroup");
		if(nullptr != deviceGroups)
		{
			for(long i = 0; i < deviceGroups->length; i++)
				DeviceGroups.push_back(XSID_AND_ATTRIBUTES(deviceGroups->item[i]));
		}
		#pragma endregion

		#pragma region RestrictedDeviceGroups
		msxml_nt restrictedDeviceGroups = xml->selectNodes(L"RestrictedDeviceGroups/RestrictedDeviceGroup");
		if(nullptr != restrictedDeviceGroups)
		{
			for(long i = 0; i < restrictedDeviceGroups->length; i++)
				RestrictedDeviceGroups.push_back(XSID_AND_ATTRIBUTES(restrictedDeviceGroups->item[i]));
		}
		#pragma endregion

		#pragma region Statistics
		msxml_et statistics = xml->selectSingleNode(L"Statistics");
		if(nullptr == statistics)
			throw std::exception("XTOKEN: cannot find 'Statistics' XML node");

		Statistics = std::make_shared<XTOKEN_STATISTICS>(statistics);
		#pragma endregion

		#pragma region MandatoryPolicy
		msxml_et mandatoryPolicy = xml->selectSingleNode(L"MandatoryPolicy");
		if(nullptr == mandatoryPolicy)
			throw std::exception("XTOKEN: cannot find 'MandatoryPolicy' XML node");

		MandatoryPolicy = std::make_shared<XBITSET<32>>(mandatoryPolicy, DwordMeaningMandatoryPolicy);
		#pragma endregion

		#pragma region AppContainerNumber
		msxml_et appContainerNumber = xml->selectSingleNode(L"AppContainerNumber");
		if(nullptr == appContainerNumber)
			throw std::exception("XTOKEN: cannot find 'AppContainerNumber' XML node");

		AppContainerNumber = _variant_t(appContainerNumber->text);
		#pragma endregion

		#pragma region IsAppContainer
		msxml_et isAppContainer = xml->selectSingleNode(L"IsAppContainer");
		if(nullptr == isAppContainer)
			throw std::exception("XTOKEN: cannot find 'IsAppContainer' XML node");

		IsAppContainer = _variant_t(isAppContainer->text);
		#pragma endregion

		#pragma region SandBoxInert
		msxml_et sandBoxInert = xml->selectSingleNode(L"SandBoxInert");
		if(nullptr == sandBoxInert)
			throw std::exception("XTOKEN: cannot find 'SandBoxInert' XML node");

		SandBoxInert = _variant_t(sandBoxInert->text);
		#pragma endregion

		#pragma region VirtualizationAllowed
		msxml_et virtualizationAllowed = xml->selectSingleNode(L"VirtualizationAllowed");
		if(nullptr == virtualizationAllowed)
			throw std::exception("XTOKEN: cannot find 'VirtualizationAllowed' XML node");

		VirtualizationAllowed = _variant_t(virtualizationAllowed->text);
		#pragma endregion

		#pragma region VirtualizationEnabled
		msxml_et virtualizationEnabled = xml->selectSingleNode(L"VirtualizationEnabled");
		if(nullptr == virtualizationEnabled)
			throw std::exception("XTOKEN: cannot find 'VirtualizationEnabled' XML node");

		VirtualizationEnabled = _variant_t(virtualizationEnabled->text);
		#pragma endregion

		#pragma region LinkedToken
		msxml_et linkedToken = xml->selectSingleNode(L"LinkedToken");
		if(nullptr != linkedToken)
			LinkedToken = std::make_shared<XTOKEN>(linkedToken);
		#pragma endregion

		#pragma region AccessInformation
		msxml_et accessInformation = xml->selectSingleNode(L"AccessInformation");
		if(nullptr == accessInformation)
			throw std::exception("XTOKEN: cannot find 'AccessInformation' XML node");

		AccessInformation = std::make_shared<XTOKEN_ACCESS_INFORMATION>(accessInformation);
		#pragma endregion

		#pragma region GroupsAndPrivileges
		msxml_et groupsAndPrivileges = xml->selectSingleNode(L"GroupsAndPrivileges");
		if(nullptr == groupsAndPrivileges)
			throw std::exception("XTOKEN: cannot find 'GroupsAndPrivileges' XML node");

		GroupsAndPrivileges = std::make_shared<XTOKEN_GROUPS_AND_PRIVILEGES>(groupsAndPrivileges);
		#pragma endregion

		#pragma region UserClaimAttributes
		msxml_et userClaimAttributes = xml->selectSingleNode(L"UserClaimAttributes");
		if(nullptr != userClaimAttributes)
			UserClaimAttributes = std::make_shared<XSECURITY_ATTRIBUTES_INFORMATION>(userClaimAttributes);
		#pragma endregion

		#pragma region DeviceClaimAttributes
		msxml_et deviceClaimAttributes = xml->selectSingleNode(L"DeviceClaimAttributes");
		if(nullptr != deviceClaimAttributes)
			DeviceClaimAttributes = std::make_shared<XSECURITY_ATTRIBUTES_INFORMATION>(deviceClaimAttributes);
		#pragma endregion
	}
	//****************************************************************************************
	XTOKEN::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XTOKEN: invalid input XML");

			if((nullptr == Owner) || (nullptr == User) || (nullptr == PrimaryGroup))
				throw std::exception("XTOKEN: initialize data first");
			#pragma endregion

			#pragma region Root element
			msxml_et token = xml->createElement(std::wstring(root.value_or(L"Token")).c_str());
			if(nullptr == token)
				throw std::exception("XTOKEN: cannot create root XML node");
			#pragma endregion

			#pragma region SecurityDescriptor
			if(SecurityDescriptor)
				token->appendChild(((xml_t)*SecurityDescriptor)(xml, L"SecurityDescriptor"));
			#pragma endregion

			#pragma region SecurityAttributes
			if(SecurityAttributes)
				token->appendChild(((xml_t)*SecurityAttributes)(xml, L"SecurityAttributes"));
			#pragma endregion

			#pragma region User
			token->appendChild(((xml_t)*User)(xml, L"User"));
			#pragma endregion

			#pragma region Groups
			msxml_et groups = xml->createElement(L"Groups");
			if(nullptr == groups)
				throw std::exception("XTOKEN: cannot create 'Groups' XML node");

			for(auto&& element : Groups)
				groups->appendChild(((xml_t)element)(xml, L"Group"));

			token->appendChild(groups);
			#pragma endregion

			#pragma region Privileges
			msxml_et privileges = xml->createElement(L"Privileges");
			if(nullptr == privileges)
				throw std::exception("XTOKEN: cannot create 'Privileges' XML node");

			for(auto&& element : Privileges)
				privileges->appendChild(((xml_t)element)(xml, L"Privilege"));

			token->appendChild(privileges);
			#pragma endregion

			#pragma region Owner
			token->appendChild(((xml_t)*Owner)(xml, L"Owner"));
			#pragma endregion

			#pragma region AppContainerSid
			if(nullptr != AppContainerSid)
				token->appendChild(((xml_t)*AppContainerSid)(xml, L"AppContainerSid"));
			#pragma endregion

			#pragma region PrimaryGroup
			token->appendChild(((xml_t)*PrimaryGroup)(xml, L"PrimaryGroup"));
			#pragma endregion

			#pragma region LinkedToken
			if(nullptr != LinkedToken) // The LinkedToken could be achived only if user is in admin group 
				token->appendChild(((xml_t)*LinkedToken)(xml, L"LinkedToken"));
			#pragma endregion

			#pragma region DefaultDacl
			if(nullptr != DefaultDacl)
				token->appendChild(((xml_t)*DefaultDacl)(xml, L"DefaultDacl"));
			#pragma endregion

			#pragma region Source
			if(nullptr != Source)
				token->appendChild(((xml_t)*Source)(xml, L"Source"));
			#pragma endregion

			#pragma region Type
			msxml_et type = xml->createElement(L"Type");
			if(nullptr == type)
				throw std::exception("XTOKEN: cannot create 'Type' XML node");

			type->appendChild(xml->createTextNode(_variant_t(Type).operator _bstr_t()));

			token->appendChild(type);
			#pragma endregion

			#pragma region ImpersonationLevel
			msxml_et impersonationLevel = xml->createElement(L"ImpersonationLevel");
			if(nullptr == impersonationLevel)
				throw std::exception("XTOKEN: cannot create 'Type' XML node");

			impersonationLevel->appendChild(xml->createTextNode(_variant_t(ImpersonationLevel).operator _bstr_t()));

			token->appendChild(impersonationLevel);
			#pragma endregion

			#pragma region RestrictedSids
			msxml_et restrictedSids = xml->createElement(L"RestrictedSids");
			if(nullptr == restrictedSids)
				throw std::exception("XTOKEN: cannot create 'RestrictedSids' XML node");

			for(auto&& element : RestrictedSids)
				restrictedSids->appendChild(((xml_t)element)(xml, L"RestrictedSid"));

			token->appendChild(restrictedSids);
			#pragma endregion

			#pragma region SessionId
			msxml_et sessionId = xml->createElement(L"SessionId");
			if(nullptr == sessionId)
				throw std::exception("XTOKEN: cannot create 'SessionId' XML node");

			sessionId->appendChild(xml->createTextNode(_variant_t(SessionId).operator _bstr_t()));

			token->appendChild(sessionId);
			#pragma endregion

			#pragma region Origin
			if(nullptr != Origin)
				token->appendChild(((xml_t)*Origin)(xml, L"Origin"));
			#pragma endregion

			#pragma region Elevation
			msxml_et elevation = xml->createElement(L"Elevation");
			if(nullptr == elevation)
				throw std::exception("XTOKEN: cannot create 'Elevation' XML node");

			elevation->appendChild(xml->createTextNode(_variant_t(Elevation).operator _bstr_t()));

			token->appendChild(elevation);
			#pragma endregion

			#pragma region HasRestrictions
			msxml_et hasRestrictions = xml->createElement(L"HasRestrictions");
			if(nullptr == hasRestrictions)
				throw std::exception("XTOKEN: cannot create 'HasRestrictions' XML node");

			hasRestrictions->appendChild(xml->createTextNode(_variant_t(HasRestrictions).operator _bstr_t()));

			token->appendChild(hasRestrictions);
			#pragma endregion

			#pragma region ElevationType
			msxml_et elevationType = xml->createElement(L"ElevationType");
			if(nullptr == elevationType)
				throw std::exception("XTOKEN: cannot create 'HasRestrictions' XML node");

			elevationType->appendChild(xml->createTextNode(_variant_t(ElevationType).operator _bstr_t()));

			token->appendChild(elevationType);
			#pragma endregion

			#pragma region IntegrityLevel
			if(nullptr != IntegrityLevel)
				token->appendChild(((xml_t)*IntegrityLevel)(xml, L"IntegrityLevel"));
			#pragma endregion

			#pragma region UIAccess
			msxml_et uiAccess = xml->createElement(L"UIAccess");
			if(nullptr == uiAccess)
				throw std::exception("XTOKEN: cannot create 'UIAccess' XML node");

			uiAccess->appendChild(xml->createTextNode(_variant_t(UIAccess).operator _bstr_t()));

			token->appendChild(uiAccess);
			#pragma endregion

			#pragma region LogonSid
			if(LogonSid.empty() == false) // Could be a situation when token is from SYSTEM account and has no LogonSID
			{
				msxml_et logonSid = xml->createElement(L"LogonSids");
				if(nullptr == logonSid)
					throw std::exception("XTOKEN: cannot create 'LogonSids' XML node");

				for(auto&& element : LogonSid)
					logonSid->appendChild(((xml_t)element)(xml, L"LogonSid"));

				token->appendChild(logonSid);
			}
			#pragma endregion

			#pragma region Capabilities
			if(Capabilities.empty() == false)
			{
				msxml_et capabilities = xml->createElement(L"Capabilities");
				if(nullptr == capabilities)
					throw std::exception("XTOKEN: cannot create 'LogonSids' XML node");

				for(auto&& element : Capabilities)
					capabilities->appendChild(((xml_t)element)(xml, L"Capability"));

				token->appendChild(capabilities);
			}
			#pragma endregion

			#pragma region DeviceGroups
			if(DeviceGroups.empty() == false)
			{
				msxml_et deviceGroups = xml->createElement(L"DeviceGroups");
				if(nullptr == deviceGroups)
					throw std::exception("XTOKEN: cannot create 'DeviceGroups' XML node");

				for(auto&& element : DeviceGroups)
					deviceGroups->appendChild(((xml_t)element)(xml, L"DeviceGroup"));

				token->appendChild(deviceGroups);
			}
			#pragma endregion

			#pragma region RestrictedDeviceGroups
			if(RestrictedDeviceGroups.empty() == false)
			{
				msxml_et restrictedDeviceGroups = xml->createElement(L"RestrictedDeviceGroups");
				if(nullptr == restrictedDeviceGroups)
					throw std::exception("XTOKEN: cannot create 'RestrictedDeviceGroups' XML node");

				for(auto&& element : RestrictedDeviceGroups)
					restrictedDeviceGroups->appendChild(((xml_t)element)(xml, L"RestrictedDeviceGroup"));

				token->appendChild(restrictedDeviceGroups);
			}
			#pragma endregion

			#pragma region Statistics
			if(nullptr != Statistics)
				token->appendChild(((xml_t)*Statistics)(xml, L"Statistics"));
			#pragma endregion

			#pragma region MandatoryPolicy
			if(nullptr != MandatoryPolicy)
				token->appendChild(((xml_t)*MandatoryPolicy)(xml, L"MandatoryPolicy"));
			#pragma endregion

			#pragma region AppContainerNumber
			msxml_et appContainerNumber = xml->createElement(L"AppContainerNumber");
			if(nullptr == appContainerNumber)
				throw std::exception("XTOKEN: cannot create 'AppContainerNumber' XML node");

			appContainerNumber->appendChild(xml->createTextNode(_variant_t(AppContainerNumber).operator _bstr_t()));

			token->appendChild(appContainerNumber);
			#pragma endregion

			#pragma region IsAppContainer
			msxml_et isAppContainer = xml->createElement(L"IsAppContainer");
			if(nullptr == isAppContainer)
				throw std::exception("XTOKEN: cannot create 'IsAppContainer' XML node");

			isAppContainer->appendChild(xml->createTextNode(_variant_t(IsAppContainer).operator _bstr_t()));

			token->appendChild(isAppContainer);
			#pragma endregion

			#pragma region SandBoxInert
			msxml_et sandBoxInert = xml->createElement(L"SandBoxInert");
			if(nullptr == sandBoxInert)
				throw std::exception("XTOKEN: cannot create 'SandBoxInert' XML node");

			sandBoxInert->appendChild(xml->createTextNode(_variant_t(SandBoxInert).operator _bstr_t()));

			token->appendChild(sandBoxInert);
			#pragma endregion

			#pragma region VirtualizationAllowed
			msxml_et virtualizationAllowed = xml->createElement(L"VirtualizationAllowed");
			if(nullptr == virtualizationAllowed)
				throw std::exception("XTOKEN: cannot create 'VirtualizationAllowed' XML node");

			virtualizationAllowed->appendChild(xml->createTextNode(_variant_t(VirtualizationAllowed).operator _bstr_t()));

			token->appendChild(virtualizationAllowed);
			#pragma endregion

			#pragma region VirtualizationEnabled
			msxml_et virtualizationEnabled = xml->createElement(L"VirtualizationEnabled");
			if(nullptr == virtualizationEnabled)
				throw std::exception("XTOKEN: cannot create 'VirtualizationEnabled' XML node");

			virtualizationEnabled->appendChild(xml->createTextNode(_variant_t(VirtualizationEnabled).operator _bstr_t()));

			token->appendChild(virtualizationEnabled);
			#pragma endregion

			#pragma region AccessInformation
			if(nullptr != AccessInformation)
				token->appendChild(((xml_t)*AccessInformation)(xml, L"AccessInformation"));
			#pragma endregion

			#pragma region GroupsAndPrivileges
			if(nullptr != GroupsAndPrivileges)
				token->appendChild(((xml_t)*GroupsAndPrivileges)(xml, L"GroupsAndPrivileges"));
			#pragma endregion

			#pragma region UserClaimAttributes
			if(nullptr != UserClaimAttributes)
				token->appendChild(((xml_t)*UserClaimAttributes)(xml, L"UserClaimAttributes"));
			#pragma endregion

			#pragma region DeviceClaimAttributes
			if(nullptr != DeviceClaimAttributes)
				token->appendChild(((xml_t)*DeviceClaimAttributes)(xml, L"DeviceClaimAttributes"));
			#pragma endregion

			return token;
		};
	}
	//****************************************************************************************
	XTOKEN::operator HANDLE() const
	{
		return XTOKEN::Create(
			*User,
			*PrimaryGroup,
			Privileges,
			Groups,
			*SecurityDescriptor,
			*UserClaimAttributes,
			*DeviceClaimAttributes,
			*SecurityAttributes,
			DeviceGroups,
			*MandatoryPolicy,
			*DefaultDacl,
			*Source,
			CreateParameters.DesiredAccess,
			CreateParameters.AuthenticationId
		);
	}
	//****************************************************************************************
	BOOL XTOKEN::ChangePrivileges(const HANDLE token, const std::vector<XLUID>& privileges, const DWORD& attribute)
	{
		std::unique_ptr<TOKEN_PRIVILEGES> tp{ static_cast<PTOKEN_PRIVILEGES>(::operator new(FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[privileges.size()]))) };

		tp->PrivilegeCount = privileges.size();

		for(size_t i = 0; i < privileges.size(); i++)
			tp->Privileges[i] = { (LUID)privileges[i], attribute };

		return AdjustTokenPrivileges(
			token,
			FALSE,
			tp.get(),
			0,
			NULL,
			NULL
		);;
	}
	//****************************************************************************************
	BOOL XTOKEN::ChangePrivileges(const std::vector<std::wstring>& privileges, const HANDLE token, const DWORD& attribute)
	{
		std::vector<XLUID> luids;

		for(auto&& element : privileges)
		{
			LUID luid;
			if(!LookupPrivilegeValue(NULL, element.c_str(), &luid))
				return FALSE;

			luids.push_back(luid);
		}

		return XTOKEN::ChangePrivileges(token, luids, attribute);
	}
	//****************************************************************************************
	HANDLE XTOKEN::Create(
		const XSID_AND_ATTRIBUTES& user,
		const XSID& primaryGroup,
		const std::vector<XLUID_AND_ATTRIBUTES>& privileges,
		const std::vector<XSID_AND_ATTRIBUTES>& groups,
		const std::optional<XSD>& securityDescriptor,
		const std::optional<XSECURITY_ATTRIBUTES_INFORMATION>& userClaimAttributes,
		const std::optional<XSECURITY_ATTRIBUTES_INFORMATION>& deviceClaimAttributes,
		const std::optional<XSECURITY_ATTRIBUTES_INFORMATION>& securityAttributes,
		const std::vector<XSID_AND_ATTRIBUTES>& deviceGroups,
		const std::optional<XBITSET<32>>& mandatoryPolicy,
		const std::optional<XACL>& defaultDacl,
		const std::optional<XTOKEN_SOURCE>& source,
		const DWORD& desiredAccess,
		const std::optional<LUID>& authenticationId
	)
	{
		#pragma region Necessary definitions
		typedef struct _OBJECT_ATTRIBUTES
		{
			ULONG Length;
			HANDLE RootDirectory;
			PUNICODE_STRING ObjectName;
			ULONG Attributes; // flags
			PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
			PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
		} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

		OBJECT_ATTRIBUTES objectAttributes;
		ZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));

		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
		objectAttributes.RootDirectory = NULL;
		objectAttributes.ObjectName = NULL;
		objectAttributes.Attributes = 0x00000042; // OBJ_INHERIT | OBJ_CASE_INSENSITIVE;

		HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
		if(!ntdll)
			throw std::exception("XTOKEN: cannot load 'ntdll.dll'");

		typedef NTSTATUS(NTAPI* NTCTEX)(
			PHANDLE,                                       // [out] TokenHandle
			ACCESS_MASK,                                   // [in] DesiredAccess
			POBJECT_ATTRIBUTES,                            // [in, opt] ObjectAttributes
			TOKEN_TYPE,                                    // [in] TokenType
			PLUID,                                         // [in] AuthenticationId
			PLARGE_INTEGER,                                // [in] ExpirationTime
			PTOKEN_USER,                                   // [in] User
			PTOKEN_GROUPS,                                 // [in] Groups
			PTOKEN_PRIVILEGES,                             // [in] Privileges
			TOKEN_SECURITY_ATTRIBUTES_INFORMATION*, // [in, opt] UserAttributes
			TOKEN_SECURITY_ATTRIBUTES_INFORMATION*, // [in, opt] DeviceAttributes
			PTOKEN_GROUPS,                                 // [in, opt] DeviceGroups
			PTOKEN_MANDATORY_POLICY,                       // [in, opt] TokenMandatoryPolicy
			PTOKEN_OWNER,                                  // [in, opt] Owner
			PTOKEN_PRIMARY_GROUP,                          // [in] PrimaryGroup
			PTOKEN_DEFAULT_DACL,                           // [in, opt] DefaultDacl
			PTOKEN_SOURCE                                  // [in] TokenSource
			);
		NTCTEX NtCreateTokenEx = (NTCTEX)GetProcAddress(ntdll, "NtCreateTokenEx");
		if(!NtCreateTokenEx)
			throw std::exception("XTOKEN: cannot get address for 'NtCreateTokenEx'");

		HANDLE primary_token;
		HANDLE secondary_token;

		HANDLE result = nullptr;
		#pragma endregion

		#pragma region Get and change token for current process
		if(!OpenProcessToken(GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY_SOURCE, &primary_token))
			throw std::exception("XTOKEN: cannot get current token");

		if(FALSE == DuplicateTokenEx(primary_token, MAXIMUM_ALLOWED, nullptr, SecurityDelegation, TokenImpersonation, &secondary_token))
			throw std::exception("XTOKEN: cannot duplicate token");

		if(FALSE == XTOKEN::ChangePrivileges({ L"SeCreateTokenPrivilege" }, secondary_token, SE_PRIVILEGE_ENABLED))
			throw std::exception("XTOKEN: cannot set 'SeCreateTokenPrivilege' for current token");

		if((desiredAccess | ACCESS_SYSTEM_SECURITY) == ACCESS_SYSTEM_SECURITY)
		{
			if(FALSE == XTOKEN::ChangePrivileges({ L"SeSecurityPrivilege" }, secondary_token, SE_PRIVILEGE_ENABLED))
				throw std::exception("XTOKEN: cannot set 'SeSecurityPrivilege' for current token");
		}

		if(securityAttributes)
		{
			if(FALSE == XTOKEN::ChangePrivileges({ L"SeTcbPrivilege" }, secondary_token, SE_PRIVILEGE_ENABLED))
				throw std::exception("XTOKEN: cannot set 'SeTcbPrivilege' for current token");
		}

		#pragma region Check and change "Groups"
		std::shared_ptr<XSID> integrity_sid;
		bool has_primary_group = false;
		std::vector<XSID_AND_ATTRIBUTES> _groups;

		for(auto&& element : groups)
		{
			if(*element.Sid == primaryGroup)
				has_primary_group = true;

			if(element.Attributes->get((size_t)5 /*SE_GROUP_INTEGRITY*/) && element.Attributes->get((size_t)6 /*SE_GROUP_INTEGRITY_ENABLED*/))
			{
				if(nullptr != integrity_sid)
					throw std::exception("XTOKEN: invalid structure for Groups - multiple 'Integrity' groups");

				integrity_sid = element.Sid;
			}

			_groups.push_back(element);
		}

		if(false == has_primary_group)
		{
			_groups.push_back({
				primaryGroup,
				{ SidAndAttributesMeaningDefault, { L"SE_GROUP_MANDATORY", L"SE_GROUP_ENABLED_BY_DEFAULT", L"SE_GROUP_ENABLED" } }
			});
		}

		if(nullptr == integrity_sid)
		{
			for(auto&& element : XTOKEN::GetTokenInfo<TokenGroups>(secondary_token))
			{
				if(element.Attributes->get((size_t)5 /*SE_GROUP_INTEGRITY*/) && element.Attributes->get((size_t)6 /*SE_GROUP_INTEGRITY_ENABLED*/))
				{
					integrity_sid = element.Sid;

					_groups.push_back({
						*element.Sid,
						{ SidAndAttributesMeaningDefault, { L"SE_GROUP_INTEGRITY", L"SE_GROUP_INTEGRITY_ENABLED" } }
					});

					break;
				}
			}
		}
		#pragma endregion

		#pragma region Check and change SecurityDescriptor
		std::shared_ptr<XSD> _securityDescriptor;

		if(securityDescriptor)
		{
			#pragma region Copy SecurityDescriptor
			_securityDescriptor = std::make_shared<XSD>(securityDescriptor.value());
			#pragma endregion

			#pragma region Check Owner
			if(nullptr == _securityDescriptor->Owner)
				_securityDescriptor->Owner = XTOKEN::GetTokenInfo<TokenUser>(secondary_token)->Sid;
			#pragma endregion

			#pragma region Check SACL
			if(nullptr == _securityDescriptor->Sacl)
			{
				_securityDescriptor->Sacl = std::make_shared<XACL>(
					IL<XACE>{
						XSYSTEM_MANDATORY_LABEL_ACE(
							*integrity_sid,
							{ DwordMeaningMandatoryLabel, { L"SYSTEM_MANDATORY_LABEL_NO_WRITE_UP" } }
						)
					}
				);
			}
			else
			{
				bool label_ace_found = false;

				for(auto&& element : _securityDescriptor->Sacl->AceArray)
				{
					if(SYSTEM_MANDATORY_LABEL_ACE_TYPE == element->AceData->Type)
					{
						label_ace_found = true;
						break;
					}
				}

				if(false == label_ace_found)
				{
					_securityDescriptor->Sacl->AceArray.push_back(std::make_shared<XACE>(
						XSYSTEM_MANDATORY_LABEL_ACE(
							*integrity_sid,
							{ DwordMeaningMandatoryLabel, { L"SYSTEM_MANDATORY_LABEL_NO_WRITE_UP" } }
						)
					));
				}
			}
			#pragma endregion

			#pragma region Check DACL
			// DACL could be NULL (all SIDs allowed)
			#pragma endregion
		}
		#pragma endregion

		thread_guard guard(secondary_token);

		auto statistics = XTOKEN::GetTokenInfo<TokenStatistics>(secondary_token);

		LUID authId = authenticationId.value_or((LUID)*statistics->AuthenticationId);

		LARGE_INTEGER expirationTime;
		ZeroMemory(&expirationTime, sizeof(LARGE_INTEGER));

		memcpy(&expirationTime, &(statistics->ExpirationTime), sizeof(__int64));
		#pragma endregion

		#pragma region Make a new token
		#pragma region SecurityDescriptor
		bin_t sd{};

		if(nullptr != _securityDescriptor)
		{
			sd = (bin_t)*_securityDescriptor;
			objectAttributes.SecurityDescriptor = sd.data();
		}
		#pragma endregion

		#pragma region User
		TOKEN_USER token_user{ (SID_AND_ATTRIBUTES)user };
		#pragma endregion

		#pragma region Groups
		std::unique_ptr<TOKEN_GROUPS> token_groups{ static_cast<PTOKEN_GROUPS>(::operator new(FIELD_OFFSET(TOKEN_GROUPS, Groups[_groups.size()]))) };

		token_groups->GroupCount = _groups.size();

		for(size_t i = 0; i < _groups.size(); i++)
			token_groups->Groups[i] = (SID_AND_ATTRIBUTES)_groups[i];
		#pragma endregion

		#pragma region Privileges
		std::unique_ptr<TOKEN_PRIVILEGES> token_privileges{ static_cast<PTOKEN_PRIVILEGES>(::operator new(FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[privileges.size()]))) };

		token_privileges->PrivilegeCount = privileges.size();

		for(size_t i = 0; i < privileges.size(); i++)
			token_privileges->Privileges[i] = (LUID_AND_ATTRIBUTES)(privileges[i]);
		#pragma endregion

		#pragma region UserClaimAttributes
		// If we would have attributes with same names then system would "collapse" them into one
		std::unique_ptr<TOKEN_SECURITY_ATTRIBUTES_INFORMATION> token_userClaimAttributes;

		if(userClaimAttributes)
			token_userClaimAttributes = std::make_unique<TOKEN_SECURITY_ATTRIBUTES_INFORMATION>((TOKEN_SECURITY_ATTRIBUTES_INFORMATION)userClaimAttributes.value());
		#pragma endregion

		#pragma region DeviceClaimAttributes
		// If we would have attributes with same names then system would "collapse" them into one
		std::unique_ptr<TOKEN_SECURITY_ATTRIBUTES_INFORMATION> token_deviceClaimAttributes;

		if(deviceClaimAttributes)
			token_deviceClaimAttributes = std::make_unique<TOKEN_SECURITY_ATTRIBUTES_INFORMATION>((TOKEN_SECURITY_ATTRIBUTES_INFORMATION)deviceClaimAttributes.value());
		#pragma endregion

		#pragma region DeviceGroups
		std::unique_ptr<TOKEN_GROUPS> token_deviceGroups;

		if(deviceGroups.size())
		{
			token_deviceGroups = std::unique_ptr<TOKEN_GROUPS>{ static_cast<PTOKEN_GROUPS>(::operator new(FIELD_OFFSET(TOKEN_GROUPS, Groups[deviceGroups.size()]))) };

			token_deviceGroups->GroupCount = deviceGroups.size();

			for(size_t i = 0; i < deviceGroups.size(); i++)
				token_deviceGroups->Groups[i] = (SID_AND_ATTRIBUTES)deviceGroups[i];
		}
		#pragma endregion

		#pragma region MandatoryPolicy
		TOKEN_MANDATORY_POLICY token_mandatoryPolicy{ 0x00000001 }; // TOKEN_MANDATORY_POLICY_NO_WRITE_UP

		if(mandatoryPolicy)
			token_mandatoryPolicy.Policy = dword_vec((bin_t)mandatoryPolicy.value());
		#pragma endregion

		#pragma region PrimaryGroup
		TOKEN_PRIMARY_GROUP token_primaryGroup{};

		auto primaryGroup_sid = (bin_t)primaryGroup;
		token_primaryGroup.PrimaryGroup = (PSID)(primaryGroup_sid.data());
		#pragma endregion

		#pragma region DefaultDacl
		TOKEN_DEFAULT_DACL token_defaultDacl{};
		bin_t defaultDaclBin{};

		if(defaultDacl)
		{
			defaultDaclBin = (bin_t)defaultDacl.value();
			token_defaultDacl.DefaultDacl = (PACL)defaultDaclBin.data();
		}
		#pragma endregion

		#pragma region Source
		TOKEN_SOURCE token_source{};

		if(source)
			token_source = (TOKEN_SOURCE)source.value();		
		else
		{
			auto _source = XTOKEN::GetTokenInfo<TokenSource>(secondary_token);

			token_source.SourceIdentifier.HighPart = _source->Luid->HighPart;
			token_source.SourceIdentifier.LowPart = _source->Luid->LowPart;

			sprintf_s(token_source.SourceName, TOKEN_SOURCE_LENGTH, _source->SourceName.c_str());
		}
		#pragma endregion

		#pragma region Call NtCreateTokenEx
		NTSTATUS status = NtCreateTokenEx(
			&result,
			desiredAccess,
			&objectAttributes,
			TokenPrimary,
			&authId,
			&expirationTime,
			&token_user,
			token_groups.get(),
			token_privileges.get(),
			token_userClaimAttributes.get(),
			token_deviceClaimAttributes.get(),
			token_deviceGroups.get(),
			&token_mandatoryPolicy,
			nullptr, // It is possible to set Owner value, but in all cases it should be "Owner = User". And with "Owner = NULL" system will do same for us
			&token_primaryGroup,
			&token_defaultDacl,
			&token_source
		);

		if(status != STATUS_SUCCESS)
		{
			HMODULE advdll = LoadLibraryW(L"advapi32.dll");
			if(!advdll)
				throw std::exception("XTOKEN:cannot load 'advapi32.dll'");

			typedef ULONG(NTAPI* NTWE)(NTSTATUS);
			NTWE LsaNtStatusToWinError = (NTWE)GetProcAddress(advdll, "LsaNtStatusToWinError");
			if(!LsaNtStatusToWinError)
				throw std::exception("XTOKEN: cannot find 'LsaNtStatusToWinError' function");

			#pragma region Format information about the error
			std::stringstream stream;
			stream << "XTOKEN: cannot create a new token with specified values, error #" << LsaNtStatusToWinError(status);
			#pragma endregion

			throw std::exception(stream.str().c_str());
		}
		#pragma endregion

		#pragma region SecurityAttributes
		if(securityAttributes)
		{
			auto attrs_and_operations = std::make_unique<TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION>();

			std::vector<TOKEN_SECURITY_ATTRIBUTE_OPERATION> operations(securityAttributes.value().Attributes.size(), SaOperationAdd);
			attrs_and_operations->Operations = operations.data();

			auto info = (TOKEN_SECURITY_ATTRIBUTES_INFORMATION)securityAttributes.value();
			attrs_and_operations->Attributes = &info;

			// Each attribute must have an unique name or 'SetTokenInformation' will fail on duplicates
			if(FALSE == ::SetTokenInformation(result, TokenSecurityAttributes, attrs_and_operations.get(), sizeof(TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION)))
				throw std::exception("XTOKEN: cannot set 'SecurityAttributes'");
		}
		#pragma endregion
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
};
//********************************************************************************************

