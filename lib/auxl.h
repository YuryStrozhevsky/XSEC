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
	#pragma region Additional structures necessary for Token processing
	//****************************************************************************************
	typedef struct _LSA_UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING;

	typedef LSA_UNICODE_STRING UNICODE_STRING, * PUNICODE_STRING;
	//********************************************************************************************
	typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
	{
		DWORD64 Version;
		UNICODE_STRING Name;
	} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;
	//****************************************************************************************
	typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
	{
		UNICODE_STRING Name;
		WORD ValueType;
		WORD Reserved;
		DWORD Flags;
		DWORD ValueCount;
		union
		{
			PLONG64 pInt64;
			PDWORD64 pUint64;
			PUNICODE_STRING ppString;
			PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
			PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
		} Values;
	} TOKEN_SECURITY_ATTRIBUTE_V1, * PTOKEN_SECURITY_ATTRIBUTE_V1;
	//****************************************************************************************
	typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
	{
		WORD Version;
		WORD Reserved;
		DWORD AttributeCount;
		union
		{
			PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
		} Attribute;
	} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;
	//****************************************************************************************
	typedef enum _TOKEN_SECURITY_ATTRIBUTE_OPERATION
	{
		SaOperationNone = 0,
		SaOperationReplaceAll,
		SaOperationAdd,
		SaOperationDelete,
		SaOperationReplace
	} TOKEN_SECURITY_ATTRIBUTE_OPERATION, * PTOKEN_SECURITY_ATTRIBUTE_OPERATION;
	//****************************************************************************************
	typedef struct _TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION
	{
		TOKEN_SECURITY_ATTRIBUTES_INFORMATION* Attributes;
		TOKEN_SECURITY_ATTRIBUTE_OPERATION* Operations;
	} TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION;
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with SID_AND_ATTRIBUTES structure
	//****************************************************************************************
	struct XSID_AND_ATTRIBUTES
	{
		XSID_AND_ATTRIBUTES() = delete;
		~XSID_AND_ATTRIBUTES() = default;

		XSID_AND_ATTRIBUTES(const XSID_AND_ATTRIBUTES& copy) : Sid(copy.Sid), Attributes(copy.Attributes), Meaning(copy.Meaning) {}

		XSID_AND_ATTRIBUTES(const XSID&, const XBITSET<32> & = { SidAndAttributesMeaningDefault, { L"SE_GROUP_ENABLED" } });

		XSID_AND_ATTRIBUTES(const SID_AND_ATTRIBUTES&, const dword_meaning_t& = SidAndAttributesMeaningDefault);
		XSID_AND_ATTRIBUTES(const msxml_et&, const dword_meaning_t& = SidAndAttributesMeaningDefault);

		explicit operator xml_t() const;
		explicit operator SID_AND_ATTRIBUTES() const;

		std::shared_ptr<XSID> Sid;
		std::shared_ptr<XBITSET<32>> Attributes;

		dword_meaning_t Meaning;

		private:
		std::unique_ptr<bin_t> sid = std::make_unique<bin_t>();
	};
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::XSID_AND_ATTRIBUTES(const XSID& _sid, const XBITSET<32>& _attributes)
	{
		Sid = std::make_shared<XSID>(_sid);
		Attributes = std::make_shared<XBITSET<32>>(_attributes);
		Meaning = _attributes.Meaning;
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::XSID_AND_ATTRIBUTES(const SID_AND_ATTRIBUTES& data, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region Sid
		Sid = std::make_shared<XSID>((BYTE*)data.Sid);
		#pragma endregion

		#pragma region Attributes
		Attributes = std::make_shared<XBITSET<32>>((BYTE*)&(data.Attributes), Meaning);
		#pragma endregion
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::XSID_AND_ATTRIBUTES(const msxml_et& xml, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("SID_AND_ATTRIBUTES: invalid input XML");
		#pragma endregion

		#pragma region Sid
		msxml_et _sid = xml->selectSingleNode(L"SID");
		if(nullptr == _sid)
			throw std::exception("SID_AND_ATTRIBUTES: cannot find 'SID' XML node");

		Sid = std::make_shared<XSID>(_sid);
		#pragma endregion

		#pragma region Attributes
		msxml_et attributes = xml->selectSingleNode(L"Attributes");
		if(nullptr == attributes)
			throw std::exception("SID_AND_ATTRIBUTES: cannot find 'Attributes' XML node");

		Attributes = std::make_shared<XBITSET<32>>(attributes, Meaning);
		#pragma endregion
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("SID_AND_ATTRIBUTES: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et saa = xml->createElement(std::wstring(root.value_or(L"SID_AND_ATTRIBUTES")).c_str());
			if(nullptr == saa)
				throw std::exception("SID_AND_ATTRIBUTES: cannot create root XML node");
			#pragma endregion

			#pragma region Sid
			if(nullptr == Sid)
				throw std::exception("SID_AND_ATTRIBUTES: initialize data first");

			saa->appendChild(((xml_t)*Sid)(xml, std::nullopt));
			#pragma endregion

			#pragma region Attributes
			if(nullptr == Attributes)
				throw std::exception("SID_AND_ATTRIBUTES: initialize data first");

			saa->appendChild(((xml_t)*Attributes)(xml, L"Attributes"));
			#pragma endregion

			return saa;
		};
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::operator SID_AND_ATTRIBUTES() const
	{
		if((nullptr == Sid) || (nullptr == Attributes))
			throw std::exception("SID_AND_ATTRIBUTES: initialize data first");

		SID_AND_ATTRIBUTES result{};

		*sid = (bin_t)*Sid;

		result.Sid = (PSID)sid->data();
		result.Attributes = dword_vec((bin_t)*Attributes);

		return result;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with SID_AND_ATTRIBUTES_HASH structure
	//****************************************************************************************
	struct XSID_AND_ATTRIBUTES_HASH
	{
		XSID_AND_ATTRIBUTES_HASH() = delete;
		~XSID_AND_ATTRIBUTES_HASH() = default;

		XSID_AND_ATTRIBUTES_HASH(const std::vector<XSID_AND_ATTRIBUTES>&, const std::vector<bin_t>&);

		XSID_AND_ATTRIBUTES_HASH(const SID_AND_ATTRIBUTES_HASH&, const dword_meaning_t& = SidAndAttributesMeaningDefault);
		XSID_AND_ATTRIBUTES_HASH(const msxml_et&, const dword_meaning_t& = SidAndAttributesMeaningDefault);

		explicit operator xml_t() const;

		std::vector<XSID_AND_ATTRIBUTES> Attributes;
		std::vector<bin_t> Hashes;

		dword_meaning_t Meaning;
	};
	//****************************************************************************************
	XSID_AND_ATTRIBUTES_HASH::XSID_AND_ATTRIBUTES_HASH(const std::vector<XSID_AND_ATTRIBUTES>& attributes, const std::vector<bin_t>& hashes) : Attributes(attributes), Hashes(hashes)
	{
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES_HASH::XSID_AND_ATTRIBUTES_HASH(const SID_AND_ATTRIBUTES_HASH& data, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		for(DWORD i = 0; i < data.SidCount; i++)
		{
			Attributes.push_back(XSID_AND_ATTRIBUTES(data.SidAttr[i], meaning));

			//// Documentation says it is "An array of pointers to hash values", but it is not.
			//// Untill I found a way how to deal with the value I comment it
			//unsigned char* pointer = (unsigned char*)data.Hash[i];

			//Hashes.push_back(bin_t{ pointer, pointer + SID_HASH_SIZE });
		}
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES_HASH::XSID_AND_ATTRIBUTES_HASH(const msxml_et& xml, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("SID_AND_ATTRIBUTES_HASH: invalid input XML");
		#pragma endregion

		#pragma region SidAttr
		Attributes.clear();

		msxml_nt sidAttrs = xml->selectNodes(L"Attribute");
		if(nullptr == sidAttrs)
			throw std::exception("SID_AND_ATTRIBUTES_HASH: cannot find 'SidAttrs' XML node");

		for(long i = 0; i < sidAttrs->length; i++)
			Attributes.push_back(XSID_AND_ATTRIBUTES(sidAttrs->item[i], meaning));
		#pragma endregion

		#pragma region Hash
		msxml_nt hashes = xml->selectNodes(L"Hash");
		if(nullptr == hashes)
			throw std::exception("SID_AND_ATTRIBUTES_HASH: cannot find 'Hash' XML node");

		for(long i = 0; i < hashes->length; i++)
			Hashes.push_back(from_hex_codes((wchar_t*)hashes->item[i]->text));
		#pragma endregion
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES_HASH::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("SID_AND_ATTRIBUTES_HASH: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et saa = xml->createElement(std::wstring(root.value_or(L"SID_AND_ATTRIBUTES_HASH")).c_str());
			if(nullptr == saa)
				throw std::exception("SID_AND_ATTRIBUTES_HASH: cannot create root XML");
			#pragma endregion

			#pragma region Attributes
			for(auto&& element : Attributes)
				saa->appendChild(((xml_t)element)(xml, L"Attribute"));
			#pragma endregion

			#pragma region Hash
			for(auto&& element : Hashes)
			{
				msxml_et hash = xml->createElement(L"Hash");
				if(nullptr == hash)
					throw std::exception("SID_AND_ATTRIBUTES_HASH: cannot create 'Hash' XML node");

				hash->appendChild(xml->createTextNode(whex_codes(element).c_str()));

				saa->appendChild(hash);
			}
			#pragma endregion

			return saa;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with LUID structure
	//****************************************************************************************
	struct XLUID
	{
		XLUID() = delete;
		~XLUID() = default;

		XLUID(const DWORD&, const LONG&);

		XLUID(const LUID);
		XLUID(const std::wstring);
		XLUID(const msxml_et&);

		bool operator==(XLUID) const;

		explicit operator xml_t() const;
		operator LUID() const;

		DWORD LowPart = 0;
		LONG HighPart = 0;

		#pragma region Static declaratiosn for wel-known LUIDs
		static const XLUID System;
		static const XLUID Anonymous;
		static const XLUID LocalService;
		static const XLUID NetworkService;
		#pragma endregion
	};
	//****************************************************************************************
	const XLUID XLUID::System = { 0x3e7, 0 };
	const XLUID XLUID::Anonymous = { 0x3e6, 0 };
	const XLUID XLUID::LocalService = { 0x3e5, 0 };
	const XLUID XLUID::NetworkService = { 0x3e4, 0 };
	//****************************************************************************************
	XLUID::XLUID(const DWORD& low, const LONG& high) : LowPart(low), HighPart(high)
	{
	}
	//****************************************************************************************
	XLUID::XLUID(const LUID luid) : LowPart(luid.LowPart), HighPart(luid.HighPart)
	{
	}
	//****************************************************************************************
	XLUID::XLUID(const std::wstring name)
	{
		LUID luid;

		if(!LookupPrivilegeValue(nullptr, name.c_str(), &luid))
			throw std::exception("LUID: Cannot find correct LUID for name");

		LowPart = luid.LowPart;
		HighPart = luid.HighPart;
	}
	//****************************************************************************************
	XLUID::XLUID(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("LUID: invalid input XML");
		#pragma endregion

		#pragma region Luid
		msxml_et highPart = xml->selectSingleNode(L"HighPart");
		if(nullptr == highPart)
			throw std::exception("LUID: cannot find 'HighPart' XML node");

		HighPart = dword_vec(from_hex_codes((wchar_t*)highPart->text));

		msxml_et lowPart = xml->selectSingleNode(L"LowPart");
		if(nullptr == lowPart)
			throw std::exception("LUID: cannot find 'LowPart' XML node");

		LowPart = dword_vec(from_hex_codes((wchar_t*)lowPart->text));
		#pragma endregion
	}
	//****************************************************************************************
	bool XLUID::operator ==(XLUID luid) const
	{
		return ((HighPart == luid.HighPart) && (LowPart == luid.LowPart));
	}
	//****************************************************************************************
	XLUID::operator LUID() const
	{
		LUID result = {};

		result.HighPart = HighPart;
		result.LowPart = LowPart;

		return result;
	}
	//****************************************************************************************
	XLUID::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("LUID: invalid input XML");
			#pragma endregion

			#pragma region Initialize common LUID structure
			LUID luid{};

			luid.HighPart = HighPart;
			luid.LowPart = LowPart;
			#pragma endregion

			#pragma region Root element
			msxml_et luidXML = xml->createElement(std::wstring(root.value_or(L"LUID")).c_str());
			if(nullptr == luidXML)
				throw std::exception("LUID: cannot create root XML node");

			#pragma region Trying to get additional information specific for privileges
			DWORD privilegeNameSize = 0;

			if(!LookupPrivilegeName(nullptr, &luid, nullptr, &privilegeNameSize))
			{
				// Sometimes the "LookupPrivilegeName" could have "access denied" for specific thread tokens
				// In order to lookup name of privileges on current system token need to have rights
				if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					std::wstring privilegeNameStr;
					privilegeNameStr.resize(privilegeNameSize - 1);

					if(LookupPrivilegeName(nullptr, &luid, privilegeNameStr.data(), &privilegeNameSize))
					{
						msxml_at privilegeName = xml->createAttribute(L"PrivilegeName");

						privilegeName->value = privilegeNameStr.c_str();
						luidXML->setAttributeNode(privilegeName);

						DWORD privilegeDisplayNameSize = 0;
						DWORD language = 0;

						if(!LookupPrivilegeDisplayName(nullptr, privilegeNameStr.data(), nullptr, &privilegeDisplayNameSize, &language))
						{
							if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
							{
								std::wstring privilegeDisplayNameStr;
								privilegeDisplayNameStr.resize(privilegeDisplayNameSize - 1);

								if(LookupPrivilegeDisplayName(nullptr, privilegeNameStr.data(), privilegeDisplayNameStr.data(), &privilegeDisplayNameSize, &language))
								{
									msxml_at privilegeDisplayName = xml->createAttribute(L"PrivilegeDisplayName");

									privilegeDisplayName->value = privilegeDisplayNameStr.c_str();
									luidXML->setAttributeNode(privilegeDisplayName);
								}
							}
						}
					}
				}
			}
			#pragma endregion
			#pragma endregion

			#pragma region Luid
			#pragma region LUID high part
			msxml_et highPart = xml->createElement(L"HighPart");
			if(nullptr == highPart)
				throw std::exception("LUID: cannot create 'HighPart' XML node");

			highPart->appendChild(xml->createTextNode(hex_codes(vec_dword(HighPart)).c_str()));

			luidXML->appendChild(highPart);
			#pragma endregion

			#pragma region LUID low part
			msxml_et lowPart = xml->createElement(L"LowPart");
			if(nullptr == lowPart)
				throw std::exception("LUID: cannot create 'LowPart' XML node");

			lowPart->appendChild(xml->createTextNode(hex_codes(vec_dword(LowPart)).c_str()));

			luidXML->appendChild(lowPart);
			#pragma endregion
			#pragma endregion

			return luidXML;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with LUID_AND_ATTRIBUTES structure
	//****************************************************************************************
	struct XLUID_AND_ATTRIBUTES
	{
		XLUID_AND_ATTRIBUTES() = delete;
		~XLUID_AND_ATTRIBUTES() = default;

		XLUID_AND_ATTRIBUTES(const XLUID&, const XBITSET<32> & = { DwordMeaningPrivilege , { L"SE_PRIVILEGE_ENABLED" } });
		XLUID_AND_ATTRIBUTES(const std::wstring&, const XBITSET<32>& = { DwordMeaningPrivilege , { L"SE_PRIVILEGE_ENABLED" } });

		XLUID_AND_ATTRIBUTES(const LUID_AND_ATTRIBUTES&, const dword_meaning_t& = DwordMeaningPrivilege);
		XLUID_AND_ATTRIBUTES(const msxml_et&, const dword_meaning_t & = DwordMeaningPrivilege);

		operator LUID_AND_ATTRIBUTES() const;
		operator xml_t() const;

		std::shared_ptr<XLUID> Luid;
		std::shared_ptr<XBITSET<32>> Attributes;
	};
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::XLUID_AND_ATTRIBUTES(const XLUID& luid, const  XBITSET<32>& attributes)
	{
		Luid = std::make_shared<XLUID>(luid);
		Attributes = std::make_shared<XBITSET<32>>(attributes);
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::XLUID_AND_ATTRIBUTES(const std::wstring& privilege, const XBITSET<32>& attributes)
	{
		LUID luid;
		if(!LookupPrivilegeValue(NULL, privilege.c_str(), &luid))
			throw std::exception("XLUID_AND_ATTRIBUTES: cannot find privilege LUID by name");

		Luid = std::make_shared<XLUID>(luid);
		Attributes = std::make_shared<XBITSET<32>>(attributes);
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::XLUID_AND_ATTRIBUTES(const LUID_AND_ATTRIBUTES& luid_attrs, const dword_meaning_t& meaning)
	{
		Luid = std::make_shared<XLUID>(luid_attrs.Luid);
		Attributes = std::make_shared<XBITSET<32>>(luid_attrs.Attributes, meaning);
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::XLUID_AND_ATTRIBUTES(const msxml_et& xml, const dword_meaning_t& meaning)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("LUID_AND_ATTRIBUTES: invalid input XML");
		#pragma endregion

		#pragma region Luid
		msxml_et luid = xml->selectSingleNode(L"LUID");
		if(nullptr == luid)
			throw std::exception("LUID_AND_ATTRIBUTES: cannot find 'LUID' XML node");

		Luid = std::make_shared<XLUID>(luid);
		#pragma endregion

		#pragma region Attributes
		msxml_et attributes = xml->selectSingleNode(L"Attributes");
		if(nullptr == attributes)
			throw std::exception("LUID_AND_ATTRIBUTES: cannot find 'Attributes' XML node");

		Attributes = std::make_shared<XBITSET<32>>(attributes, meaning);;
		#pragma endregion
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::operator LUID_AND_ATTRIBUTES() const
	{
		if((nullptr == Luid) || (nullptr == Attributes))
			throw std::exception("LUID_AND_ATTRIBUTES: initialize data first");

		LUID_AND_ATTRIBUTES result{};

		result.Luid.HighPart = Luid->HighPart;
		result.Luid.LowPart = Luid->LowPart;

		result.Attributes = dword_vec((bin_t)*Attributes);

		return result;
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("LUID_AND_ATTRIBUTES: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et laa = xml->createElement(std::wstring(root.value_or(L"LUID_AND_ATTRIBUTES")).c_str());
			if(nullptr == laa)
				throw std::exception("LUID_AND_ATTRIBUTES: cannot create root XML node");
			#pragma endregion

			#pragma region Luid
			if(nullptr == Luid)
				throw std::exception("LUID_AND_ATTRIBUTES: initialize data first");

			laa->appendChild(((xml_t)*Luid)(xml, L"LUID"));
			#pragma endregion

			#pragma region Attributes
			if(nullptr == Attributes)
				throw std::exception("LUID_AND_ATTRIBUTES: initialize data first");

			laa->appendChild(((xml_t)*Attributes)(xml, L"Attributes"));
			#pragma endregion

			return laa;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with GUID
	//****************************************************************************************
	struct XGUID
	{
		XGUID() = delete;
		~XGUID() = default;

		XGUID(const GUID&);
		XGUID(const std::wstring&);
		XGUID(const bin_t&);
		XGUID(const msxml_et&);

		static XGUID Create();

		explicit operator bin_t() const;
		explicit operator GUID() const;
		explicit operator std::wstring() const;
		explicit operator xml_t() const;

		bin_t Value;

	private:
		void FromString(const std::wstring&);
	};
	//****************************************************************************************
	XGUID XGUID::Create()
	{
		GUID guid;
		ZeroMemory(&guid, sizeof(GUID));

		HRESULT hr = CoCreateGuid(&guid);
		if(S_OK != hr)
			throw std::exception("XGUID: cannot create GUID");

		return XGUID(guid);
	}
	//****************************************************************************************
	XGUID::XGUID(const GUID& value)
	{
		Value.resize(16);
		std::copy_n((unsigned char*)&value, 16, Value.begin());
	}
	//****************************************************************************************
	void XGUID::FromString(const std::wstring& value)
	{
		#pragma region Initial variables
		std::wstringstream stream;

		std::wregex regex(L"([0-9a-fA-F]{8})-{0,1}([0-9a-fA-F]{4})-{0,1}([0-9a-fA-F]{4})-{0,1}([0-9a-fA-F]{4})-{0,1}([0-9a-fA-F]{12})");
		std::match_results<std::wstring::const_iterator> match;
		#pragma endregion

		#pragma region Check input string format
		if(false == std::regex_match(value, match, regex))
			throw std::exception("XGUID: invalid format of the input string");
		#pragma endregion

		#pragma region Parse input string
		for(size_t i = 1; i < 6; i++)
		{
			size_t index = 0;

			std::wstring value = match[i];
			std::vector<std::wstring> chunks(value.size() >> 1, std::wstring{ 2, L' ' });

			for(auto j = value.begin(); j != value.end(); j += 2)
				std::copy_n(j, 2, chunks[index++].begin());

			if(i < 4)
				std::reverse(chunks.begin(), chunks.end());

			std::copy(chunks.begin(), chunks.end(), std::ostream_iterator<std::wstring, wchar_t>(stream, L" "));
		}
		#pragma endregion

		#pragma region Convert string to binary format
		Value = XSEC::from_hex_codes(stream.str());
		#pragma endregion
	}
	//****************************************************************************************
	XGUID::XGUID(const std::wstring& value)
	{
		FromString(value);
	}
	//****************************************************************************************
	XGUID::XGUID(const bin_t& value)
	{
		if(value.size() != 16)
			throw std::exception("XGUID: invalid input value");

		Value = value;
	}
	//****************************************************************************************
	XGUID::XGUID(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XGUID: incorrect input XML");
		#pragma endregion

		FromString((wchar_t*)xml->text);
	}
	//****************************************************************************************
	XGUID::operator bin_t() const
	{
		return Value;
	}
	//****************************************************************************************
	XGUID::operator GUID() const
	{
		return *(GUID*)Value.data();
	}
	//****************************************************************************************
	XGUID::operator std::wstring() const
	{
		#pragma region Initial variables
		std::wstring hex = XSEC::whex_codes(Value);
		hex.erase(std::remove(hex.begin(), hex.end(), L' '), hex.end());

		std::wstringstream stream;

		std::wregex regex(L"([0-9a-fA-F]{8})-{0,1}([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{12})");
		std::match_results<std::wstring::const_iterator> match;
		#pragma endregion

		#pragma region Check input string format
		if(false == std::regex_match(hex, match, regex))
			throw std::exception("XGUID: invalid Value");
		#pragma endregion

		#pragma region Parse input string
		for(size_t i = 1; i < 6; i++)
		{
			size_t index = 0;

			std::wstring value = match[i];
			std::vector<std::wstring> chunks(value.size() >> 1, std::wstring{ 2, L' ' });

			for(auto j = value.begin(); j != value.end(); j += 2)
				std::copy_n(j, 2, chunks[index++].begin());

			if(i < 4)
				std::reverse(chunks.begin(), chunks.end());

			if((size_t)stream.tellp())
				stream << L"-";

			std::copy(chunks.begin(), chunks.end(), std::ostream_iterator<std::wstring, wchar_t>(stream));
		}
		#pragma endregion

		return stream.str();
	}
	//****************************************************************************************
	XGUID::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XSID: invalid output XML");
			#pragma endregion

			#pragma region Root element
			msxml_et guid = xml->createElement(std::wstring(root.value_or(L"GUID")).c_str());
			guid->appendChild(xml->createTextNode(((std::wstring)*this).c_str()));
			#pragma endregion

			return guid;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class fo working with OBJECT_TYPE_LIST
	//****************************************************************************************
	struct XOBJECT_TYPE_LIST
	{
		XOBJECT_TYPE_LIST() = delete;
		~XOBJECT_TYPE_LIST() = default;

		XOBJECT_TYPE_LIST(const OBJECT_TYPE_LIST&);
		XOBJECT_TYPE_LIST(const bin_t&, const WORD& = 0);
		XOBJECT_TYPE_LIST(const std::wstring&, const WORD& = 0);

		explicit operator OBJECT_TYPE_LIST();

		WORD Level = 0;
		std::shared_ptr<XGUID> ObjectType;
	};
	//****************************************************************************************
	XOBJECT_TYPE_LIST::XOBJECT_TYPE_LIST(const OBJECT_TYPE_LIST& list) : Level(list.Level), ObjectType(std::make_shared<XGUID>(*list.ObjectType))
	{
	}
	//****************************************************************************************
	XOBJECT_TYPE_LIST::XOBJECT_TYPE_LIST(const bin_t& objectType, const WORD& level) : Level(level), ObjectType(std::make_shared<XGUID>(objectType))
	{
	}
	//****************************************************************************************
	XOBJECT_TYPE_LIST::XOBJECT_TYPE_LIST(const std::wstring& objectType, const WORD& level) : Level(level), ObjectType(std::make_shared<XGUID>(objectType))
	{
	}
	//****************************************************************************************
	XOBJECT_TYPE_LIST::operator OBJECT_TYPE_LIST()
	{
		if(nullptr == ObjectType)
			throw std::exception("XOBJECT_TYPE_LIST: initialize data first");

		return { Level, 0, (GUID*)ObjectType->Value.data() };
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
};
//********************************************************************************************

