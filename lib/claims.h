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
	#pragma region Class for working with XSECURITY_ATTRIBUTE_FQBN_VALUE structure (XTOKEN and CLAIM)
	//****************************************************************************************
	struct XSECURITY_ATTRIBUTE_FQBN_VALUE
	{
		XSECURITY_ATTRIBUTE_FQBN_VALUE() = delete;
		~XSECURITY_ATTRIBUTE_FQBN_VALUE() = default;

		XSECURITY_ATTRIBUTE_FQBN_VALUE(const std::wstring&, const DWORD64& = 1);

		XSECURITY_ATTRIBUTE_FQBN_VALUE(const CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE&);
		XSECURITY_ATTRIBUTE_FQBN_VALUE(const TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE&);
		XSECURITY_ATTRIBUTE_FQBN_VALUE(const msxml_et&);

		explicit operator CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE() const;
		explicit operator TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE() const;
		explicit operator xml_t() const;

		DWORD64 Version = 1;
		std::wstring Name;
	};
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_FQBN_VALUE XFQBN(const std::wstring& string, const DWORD64& version = 0)
	{
		return XSECURITY_ATTRIBUTE_FQBN_VALUE(string, version);
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_FQBN_VALUE::XSECURITY_ATTRIBUTE_FQBN_VALUE(const std::wstring& name, const DWORD64& version) : Version(version), Name(name)
	{
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_FQBN_VALUE::XSECURITY_ATTRIBUTE_FQBN_VALUE(const CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE& value) : Version(value.Version), Name(value.Name)
	{
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_FQBN_VALUE::XSECURITY_ATTRIBUTE_FQBN_VALUE(const TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE& value) : Version(value.Version)
	{
		Name.clear();
		Name.resize(value.Name.Length);
		memcpy(Name.data(), value.Name.Buffer, value.Name.Length);
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_FQBN_VALUE::XSECURITY_ATTRIBUTE_FQBN_VALUE(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XSECURITY_ATTRIBUTE_FQBN_VALUE: invalid input XML");
		#pragma endregion

		#pragma region Version
		msxml_et version = xml->selectSingleNode(L"Version");
		if(nullptr == version)
			throw std::exception("XSECURITY_ATTRIBUTE_FQBN_VALUE: cannot find 'Version' XML node");

		Version = _variant_t(version->text);
		#pragma endregion

		#pragma region Name
		msxml_et name = xml->selectSingleNode(L"Name");
		if(nullptr == name)
			throw std::exception("XSECURITY_ATTRIBUTE_FQBN_VALUE: cannot find 'Name' XML node");

		Name = name->text;
		#pragma endregion
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_FQBN_VALUE::operator CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE() const
	{
		return { Version, (PWSTR)Name.data() };
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_FQBN_VALUE::operator TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE() const
	{
		TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE result{};

		result.Version = Version;

		#pragma region Name
		#pragma warning(push)
		#pragma warning(disable:4267)
		result.Name.Length = Name.size() * sizeof(wchar_t);
		result.Name.MaximumLength = Name.size() * sizeof(wchar_t);
		#pragma warning(pop)

		result.Name.Buffer = (PWSTR)Name.data();
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_FQBN_VALUE::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XSECURITY_ATTRIBUTE_FQBN_VALUE: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et cattr = xml->createElement(std::wstring(root.value_or(L"XSECURITY_ATTRIBUTE_FQBN_VALUE")).c_str());
			if(nullptr == cattr)
				throw std::exception("XSECURITY_ATTRIBUTE_FQBN_VALUE: cannot create root XML node");
			#pragma endregion

			#pragma region Version
			msxml_et version = xml->createElement(L"Version");
			if(nullptr == version)
				throw std::exception("XSECURITY_ATTRIBUTE_FQBN_VALUE: cannot create 'Version' XML node");

			version->appendChild(xml->createTextNode(_variant_t(Version).operator _bstr_t()));

			cattr->appendChild(version);
			#pragma endregion

			#pragma region Name
			msxml_et name = xml->createElement(L"Name");
			if(nullptr == name)
				return nullptr;

			name->appendChild(xml->createTextNode(Name.c_str()));

			cattr->appendChild(name);
			#pragma endregion

			return cattr;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE structure (XTOKEN and CLAIM)
	//****************************************************************************************
	struct XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE
	{
		XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE() = delete;
		~XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE() = default;

		XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE(const bin_t&);

		XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE(const CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE&);
		XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE(const msxml_et&);

		explicit operator CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE() const;
		explicit operator xml_t() const;

		bin_t Value;
	};
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE::XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE(const bin_t& value) : Value(value)
	{
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE::XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE(const CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE& value)
	{
		Value.resize(value.ValueLength);
		memcpy(Value.data(), value.pValue, value.ValueLength);
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE::XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE: invalid input XML");
		#pragma endregion

		#pragma region pValue
		Value = from_hex_codes((wchar_t*)xml->text);
		#pragma endregion
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE::operator CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE() const
	{
		return { (PVOID)Value.data(), Value.size() };
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et cattr = xml->createElement(std::wstring(root.value_or(L"XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE")).c_str());
			if(nullptr == cattr)
				throw std::exception("XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE: cannot create root XML node");
			#pragma endregion

			#pragma region pValue
			cattr->appendChild(xml->createTextNode(hex_codes(Value).c_str()));
			#pragma endregion

			return cattr;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with XSECURITY_ATTRIBUTE_V1 structure (XTOKEN and CLAIM)
	//****************************************************************************************
	struct XSECURITY_ATTRIBUTE_V1
	{
		XSECURITY_ATTRIBUTE_V1() = delete;
		~XSECURITY_ATTRIBUTE_V1() = default;

		XSECURITY_ATTRIBUTE_V1(const XSECURITY_ATTRIBUTE_V1& copy) : Name(copy.Name), ValueType(copy.ValueType), Flags(copy.Flags), Values(copy.Values)  {}

		XSECURITY_ATTRIBUTE_V1(
			const std::wstring&, 
			const WORD&, 
			const XBITSET<32>&, 
			const std::vector<std::variant<LONG64, DWORD64, std::wstring, XSECURITY_ATTRIBUTE_FQBN_VALUE, XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE, XSID>>&
		);

		XSECURITY_ATTRIBUTE_V1(const std::wstring&, const std::initializer_list<int>&, const XBITSET<32> & = { SecurityAttributeV1Meaning, { L"FCI_CLAIM_SECURITY_ATTRIBUTE_MANUAL" } });
		XSECURITY_ATTRIBUTE_V1(const std::wstring&, const std::initializer_list<LONG64>&, const XBITSET<32> & = { SecurityAttributeV1Meaning, { L"FCI_CLAIM_SECURITY_ATTRIBUTE_MANUAL" } });
		XSECURITY_ATTRIBUTE_V1(const std::wstring&, const std::initializer_list<bool>&, const XBITSET<32> & = { SecurityAttributeV1Meaning, { L"FCI_CLAIM_SECURITY_ATTRIBUTE_MANUAL" } });
		XSECURITY_ATTRIBUTE_V1(const std::wstring&, const std::initializer_list<const wchar_t*>&, const XBITSET<32> & = { SecurityAttributeV1Meaning, { L"FCI_CLAIM_SECURITY_ATTRIBUTE_MANUAL" } });
		XSECURITY_ATTRIBUTE_V1(const std::wstring&, const std::initializer_list<bin_t>&, const XBITSET<32> & = { SecurityAttributeV1Meaning, { L"FCI_CLAIM_SECURITY_ATTRIBUTE_MANUAL" } });
		XSECURITY_ATTRIBUTE_V1(const std::wstring&, const std::initializer_list<XSID>&, const XBITSET<32> & = { SecurityAttributeV1Meaning, { L"FCI_CLAIM_SECURITY_ATTRIBUTE_MANUAL" } });
		XSECURITY_ATTRIBUTE_V1(const std::wstring&, const std::initializer_list<XSECURITY_ATTRIBUTE_FQBN_VALUE>&, const XBITSET<32> & = { SecurityAttributeV1Meaning, { L"FCI_CLAIM_SECURITY_ATTRIBUTE_MANUAL" } });

		XSECURITY_ATTRIBUTE_V1(const CLAIM_SECURITY_ATTRIBUTE_V1&);
		XSECURITY_ATTRIBUTE_V1(const TOKEN_SECURITY_ATTRIBUTE_V1&);

		XSECURITY_ATTRIBUTE_V1(const bin_t&);
		XSECURITY_ATTRIBUTE_V1(const msxml_et&);

		explicit operator CLAIM_SECURITY_ATTRIBUTE_V1() const;
		explicit operator TOKEN_SECURITY_ATTRIBUTE_V1() const;

		explicit operator bin_t() const;
		explicit operator xml_t() const;

		std::wstring Name;
		WORD ValueType = 0;
		std::shared_ptr<XBITSET<32>> Flags;

		// Data in the vector has types "shared_ptr" because there are using as a "persistent buffer" when converting to other types in operators.
		// In case there are direct types each "get_if" would return a copy to initial object and at the end of block the value will disapear.
		std::vector<std::variant<LONG64, DWORD64, std::shared_ptr<std::wstring>, std::shared_ptr<XSECURITY_ATTRIBUTE_FQBN_VALUE>, std::shared_ptr<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>, std::shared_ptr<XSID>>> Values;

		private:
		// Two different buffer in order to give a user ability to cast to different types from same instance
		std::unique_ptr<bin_t> buffer_claim = std::make_unique<bin_t>();
		std::unique_ptr<bin_t> buffer_token = std::make_unique<bin_t>();

		std::unique_ptr<std::vector<bin_t>> bins = std::make_unique<std::vector<bin_t>>();
	};
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const std::wstring& name, const std::initializer_list<int>& list, const XBITSET<32>& flags) : Name(name), ValueType(CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64), Flags(std::make_shared<XBITSET<32>>(flags))
	{
		for(auto&& element : list)
			Values.push_back(static_cast<LONG64>(element));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const std::wstring& name, const std::initializer_list<LONG64>& list, const XBITSET<32>& flags) : Name(name), ValueType(CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64), Flags(std::make_shared<XBITSET<32>>(flags))
	{
		for(auto&& element : list)
			Values.push_back(element);
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const std::wstring& name, const std::initializer_list<bool>& list, const XBITSET<32>& flags) : Name(name), ValueType(CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN), Flags(std::make_shared<XBITSET<32>>(flags))
	{
		for(auto&& element : list)
			Values.push_back(static_cast<DWORD64>(element));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const std::wstring& name, const std::initializer_list<const wchar_t*>& list, const XBITSET<32>& flags) : Name(name), ValueType(CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING), Flags(std::make_shared<XBITSET<32>>(flags))
	{
		for(auto&& element : list)
			Values.push_back(std::make_shared<std::wstring>(element));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const std::wstring& name, const std::initializer_list<bin_t>& list, const XBITSET<32>& flags) : Name(name), ValueType(CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING), Flags(std::make_shared<XBITSET<32>>(flags))
	{
		for(auto&& element : list)
			Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>(element));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const std::wstring& name, const std::initializer_list<XSID>& list, const XBITSET<32>& flags) : Name(name), ValueType(CLAIM_SECURITY_ATTRIBUTE_TYPE_SID), Flags(std::make_shared<XBITSET<32>>(flags))
	{
		for(auto&& element : list)
			Values.push_back(std::make_shared<XSID>(element));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const std::wstring& name, const std::initializer_list<XSECURITY_ATTRIBUTE_FQBN_VALUE>& list, const XBITSET<32>& flags) : Name(name), ValueType(CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN), Flags(std::make_shared<XBITSET<32>>(flags))
	{
		for(auto&& element : list)
			Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_FQBN_VALUE>(element));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(
		const std::wstring& name,
		const WORD& valueType,
		const XBITSET<32>& flags,
		const std::vector<std::variant<LONG64, DWORD64, std::wstring, XSECURITY_ATTRIBUTE_FQBN_VALUE, XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE, XSID>>& values
	) : Name(name), ValueType(valueType), Flags(std::make_shared<XBITSET<32>>(flags))
	{
		switch(ValueType)
		{
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
				for(auto&& element : values)
				{
					auto get_if = std::get_if<LONG64>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					Values.push_back(*get_if);
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
				for(auto&& element : values)
				{
					auto get_if = std::get_if<DWORD64>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					Values.push_back(*get_if);
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
				for(auto&& element : values)
				{
					auto get_if = std::get_if<std::wstring>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					Values.push_back(std::make_shared<std::wstring>(*get_if));
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN:
				for(auto&& element : values)
				{
					auto get_if = std::get_if<XSECURITY_ATTRIBUTE_FQBN_VALUE>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_FQBN_VALUE>(*get_if));
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
				for(auto&& element : values)
				{
					auto get_if = std::get_if<XSID>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					Values.push_back(std::make_shared<XSID>(*get_if));
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
				for(auto&& element : values)
				{
					auto get_if = std::get_if<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>(*get_if));
				}

				break;
			default:
				throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid attribute type");
		}
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const CLAIM_SECURITY_ATTRIBUTE_V1& value)
	{
		#pragma region Name
		Name = value.Name;
		#pragma endregion

		#pragma region ValueType
		ValueType = value.ValueType;
		#pragma endregion

		#pragma region Flags
		Flags = std::make_shared<XBITSET<32>>((BYTE*)&(value.Flags), SecurityAttributeV1Meaning);
		#pragma endregion

		#pragma region Values
		switch(ValueType)
		{
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(value.Values.pInt64[i]);

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(value.Values.pUint64[i]);

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(std::make_shared<std::wstring>(value.Values.ppString[i]));
					
				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_FQBN_VALUE>(value.Values.pFqbn[i]));

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(std::make_shared<XSID>((BYTE*)(value.Values.pOctetString[i].pValue)));

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>(value.Values.pOctetString[i]));

				break;
			default:
				throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid attribute type");
		}
		#pragma endregion
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const TOKEN_SECURITY_ATTRIBUTE_V1& value)
	{
		#pragma region Name
		Name.clear();
		Name.resize(value.Name.Length);
		memcpy(Name.data(), value.Name.Buffer, value.Name.Length);
		#pragma endregion

		#pragma region ValueType
		ValueType = value.ValueType;
		#pragma endregion

		#pragma region Flags
		Flags = std::make_shared<XBITSET<32>>((BYTE*)&(value.Flags), SecurityAttributeV1Meaning);
		#pragma endregion

		#pragma region Values
		switch(ValueType)
		{
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(value.Values.pInt64[i]);

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(value.Values.pUint64[i]);

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
				for(DWORD i = 0; i < value.ValueCount; i++)
				{
					std::wstring string;
					string.resize(value.Values.ppString[i].Length);
					memcpy(string.data(), value.Values.ppString[i].Buffer, value.Values.ppString[i].Length);

					Values.push_back(std::make_shared<std::wstring>(string));
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_FQBN_VALUE>(value.Values.pFqbn[i]));

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(std::make_shared<XSID>((BYTE*)(value.Values.pOctetString[i].pValue)));

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
				for(DWORD i = 0; i < value.ValueCount; i++)
					Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>(value.Values.pOctetString[i]));

				break;
			default:
				throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid attribute type");
		}
		#pragma endregion
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::operator CLAIM_SECURITY_ATTRIBUTE_V1() const
	{
		#pragma region Initial variables
		CLAIM_SECURITY_ATTRIBUTE_V1 result{};
		result.Reserved = 0;

		size_t i = 0;
		#pragma endregion

		#pragma region Initial check
		if((ValueType == 0) || (Values.size() == 0))
			throw std::exception("XSECURITY_ATTRIBUTE_V1: initialize data first");
		#pragma endregion

		#pragma region Name
		result.Name = (PWSTR)Name.data();
		#pragma endregion

		#pragma region ValueType
		result.ValueType = ValueType;
		#pragma endregion

		#pragma region ValueCount
		result.ValueCount = Values.size();
		#pragma endregion

		#pragma region Flags
		result.Flags = dword_vec((bin_t)*Flags);
		#pragma endregion

		#pragma region Values
		switch(ValueType)
		{
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
				{
					buffer_claim->resize(Values.size() * sizeof(LONG64));

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<LONG64>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						((PLONG64)buffer_claim->data())[i++] = *get_if;
					}

					result.Values.pInt64 = (PLONG64)buffer_claim->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
				{
					buffer_claim->resize(Values.size() * sizeof(DWORD64));

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<DWORD64>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						((PDWORD64)buffer_claim->data())[i++] = *get_if;
					}

					result.Values.pUint64 = (PDWORD64)buffer_claim->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
				{
					buffer_claim->resize(Values.size() * sizeof(PWSTR));

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<std::wstring>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						// Data would be persistent because of "variant<shared_ptr>": 
						// even a copy from "get_if" points to exactly one source of data, not to a copy
						((PWSTR*)buffer_claim->data())[i++] = (PWSTR)(*get_if)->data();
					}

					result.Values.ppString = (PWSTR*)buffer_claim->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN:
				{
					buffer_claim->resize(Values.size() * sizeof(CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE));

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<XSECURITY_ATTRIBUTE_FQBN_VALUE>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						// Data would be persistent because of "variant<shared_ptr>": 
						// even a copy from "get_if" points to exactly one source of data, not to a copy
						((PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE)buffer_claim->data())[i++] = (CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE)*(*get_if);
					}

					result.Values.pFqbn = (PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE)buffer_claim->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
				{
					buffer_claim->resize(Values.size() * sizeof(CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE));
					bins->resize(Values.size());

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<XSID>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						// Need to use additional buffer_claim here because binary transformation array is not persistent
						bins->at(i) = (bin_t)*(*get_if);

						((PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_claim->data())[i].ValueLength = bins->at(i).size();
						((PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_claim->data())[i].pValue = bins->at(i).data();

						i++;
					}

					result.Values.pOctetString = (PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_claim->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
				{
					buffer_claim->resize(Values.size() * sizeof(CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE));
					bins->resize(Values.size());

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						// Data would be persistent because of "variant<shared_ptr>": 
						// even a copy from "get_if" points to exactly one source of data, not to a copy
						((PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_claim->data())[i++] = (CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)*(*get_if);
					}

					result.Values.pOctetString = (PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_claim->data();
				}

				break;
			default:
				throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid ValueType");
		}
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::operator TOKEN_SECURITY_ATTRIBUTE_V1() const
	{
		#pragma region Initial variables
		TOKEN_SECURITY_ATTRIBUTE_V1 result{};

		size_t i = 0;
		#pragma endregion

		#pragma region Initial check
		if((ValueType == 0) || (Values.size() == 0))
			throw std::exception("XSECURITY_ATTRIBUTE_V1: initialize data first");
		#pragma endregion

		#pragma region Name
		#pragma warning(push)
		#pragma warning(disable:4267)
		result.Name.Length = Name.size() * sizeof(wchar_t);
		result.Name.MaximumLength = Name.size() * sizeof(wchar_t);
		#pragma warning(pop)

		result.Name.Buffer = (PWSTR)Name.data();
		#pragma endregion

		#pragma region ValueType
		result.ValueType = ValueType;
		#pragma endregion

		#pragma region ValueCount
		result.ValueCount = Values.size();
		#pragma endregion

		#pragma region Flags
		result.Flags = dword_vec((bin_t)*Flags);
		#pragma endregion

		#pragma region Values
		switch(ValueType)
		{
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
				{
					buffer_token->resize(Values.size() * sizeof(LONG64));

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<LONG64>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						((PLONG64)buffer_token->data())[i++] = *get_if;
					}

					result.Values.pInt64 = (PLONG64)buffer_token->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
				{
					buffer_token->resize(Values.size() * sizeof(DWORD64));

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<DWORD64>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						((PDWORD64)buffer_token->data())[i++] = *get_if;
					}

					result.Values.pUint64 = (PDWORD64)buffer_token->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
				{
					buffer_token->resize(Values.size() * sizeof(UNICODE_STRING));

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<std::wstring>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						// Data would be persistent because of "variant<shared_ptr>": 
						// even a copy from "get_if" points to exactly one source of data, not to a copy
						#pragma warning(push)
						#pragma warning(disable:4267)
						((PUNICODE_STRING)buffer_token->data())[i].Length = (*get_if)->size() * sizeof(wchar_t);
						((PUNICODE_STRING)buffer_token->data())[i].MaximumLength = (*get_if)->size() * sizeof(wchar_t);
						#pragma warning(pop)
						((PUNICODE_STRING)buffer_token->data())[i].Buffer = (PWSTR)(*get_if)->data();

						i++;
					}

					result.Values.ppString = (PUNICODE_STRING)buffer_token->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN:
				{
					buffer_token->resize(Values.size() * sizeof(TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE));

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<XSECURITY_ATTRIBUTE_FQBN_VALUE>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						// Data would be persistent because of "variant<shared_ptr>": 
						// even a copy from "get_if" points to exactly one source of data, not to a copy
						((PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE)buffer_token->data())[i++] = (TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE)*(*get_if);
					}

					result.Values.pFqbn = (PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE)buffer_token->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
				{
					buffer_token->resize(Values.size() * sizeof(CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE));
					bins->resize(Values.size());

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<XSID>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						// Need to use additional buffer_token here because binary transformation array is not persistent
						bins->at(i) = (bin_t)*(*get_if);

						((PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_token->data())[i].ValueLength = bins->at(i).size();
						((PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_token->data())[i].pValue = bins->at(i).data();

						i++;
					}

					result.Values.pOctetString = (PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_token->data();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
				{
					buffer_token->resize(Values.size() * sizeof(CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE));
					bins->resize(Values.size());

					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						// Data would be persistent because of "variant<shared_ptr>": 
						// even a copy from "get_if" points to exactly one source of data, not to a copy
						((PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_token->data())[i++] = (CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE) * (*get_if);
					}

					result.Values.pOctetString = (PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)buffer_token->data();
				}

				break;
			default:
				throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid ValueType");
		}
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const bin_t& data)
	{
		#pragma region Name
		DWORD OffsetName = 0;
		((BYTE*)&OffsetName)[0] = data[0];
		((BYTE*)&OffsetName)[1] = data[1];
		((BYTE*)&OffsetName)[2] = data[2];
		((BYTE*)&OffsetName)[3] = data[3];

		Name = (wchar_t*)(data.data() + OffsetName);
		#pragma endregion

		#pragma region ValueType
		((BYTE*)&ValueType)[0] = data[4];
		((BYTE*)&ValueType)[1] = data[5];
		#pragma endregion

		#pragma region Flags
		Flags = std::make_shared<XBITSET<32>>(data.data() + 8, SecurityAttributeV1Meaning);
		#pragma endregion

		#pragma region ValueCount
		DWORD ValueCount = 0;

		((BYTE*)&ValueCount)[0] = data[12];
		((BYTE*)&ValueCount)[1] = data[13];
		((BYTE*)&ValueCount)[2] = data[14];
		((BYTE*)&ValueCount)[3] = data[15];
		#pragma endregion

		#pragma region Values
		DWORD OffsetValues = 0;
		((BYTE*)&OffsetValues)[0] = data[16];
		((BYTE*)&OffsetValues)[1] = data[17];
		((BYTE*)&OffsetValues)[2] = data[18];
		((BYTE*)&OffsetValues)[3] = data[19];

		switch(ValueType)
		{
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
				for(DWORD i = 0; i < ValueCount; i++, OffsetValues += sizeof(LONG64))
					Values.push_back(*((LONG64*)(data.data() + OffsetValues)));

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
				for(DWORD i = 0; i < ValueCount; i++, OffsetValues += sizeof(ULONG64))
					Values.push_back(*((ULONG64*)(data.data() + OffsetValues)));

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
				for(DWORD i = 0; i < ValueCount; i++)
				{
					std::wstring string = (wchar_t*)(data.data() + OffsetValues);
					OffsetValues += ((string.size() + 1) * sizeof(wchar_t));

					Values.push_back(std::make_shared<std::wstring>(string.c_str()));
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
				for(DWORD i = 0; i < ValueCount; i++)
				{
					DWORD len;
					memcpy(&len, data.data() + OffsetValues, sizeof(DWORD));
					OffsetValues += sizeof(DWORD);

					auto sid = std::make_shared<XSID>((unsigned char*)(data.data() + OffsetValues));

					if(len != sid->Length)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid length for SID element");

					OffsetValues += sid->Length;

					Values.push_back(sid);					 
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
				for(DWORD i = 0; i < ValueCount; i++)
				{
					DWORD len;
					memcpy(&len, data.data() + OffsetValues, sizeof(DWORD));
					OffsetValues += sizeof(DWORD);

					Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>(bin_t{ data.data() + OffsetValues, data.data() + OffsetValues + len }));

					OffsetValues += len;
				}

				break;
			default:
				throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid ValueType");
		}
		#pragma endregion
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::operator bin_t() const
	{
		#pragma region Initial check
		if((ValueType == 0) || (Values.size() == 0))
			throw std::exception("XSECURITY_ATTRIBUTE_V1: initialize data first");
		#pragma endregion

		#pragma region Initial variables
		bin_t result;
		size_t length = 0;
		#pragma endregion

		#pragma region Calculate data amount for "Values"
		switch(ValueType)
		{
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
				length = Values.size() * sizeof(LONG64);
				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
				length = Values.size() * sizeof(ULONG64);
				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
				for(auto&& element : Values)
				{
					auto get_if = std::get_if<std::shared_ptr<std::wstring>>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					length += ((*get_if)->size() + 1) * sizeof(WCHAR);
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
				for(auto&& element : Values)
				{
					auto get_if = std::get_if<std::shared_ptr<XSID>>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					length += (((bin_t)*(*get_if)).size() + sizeof(DWORD));
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
				for(auto&& element : Values)
				{
					auto get_if = std::get_if<std::shared_ptr<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					length += ((*get_if)->Value.size() + sizeof(DWORD));
				}

				break;
			default:
				// Other claim types are not implemented
				break;
		}

		length = length + 20 + (Name.size() + 1) * sizeof(wchar_t);
		length += (4 - (length % 4));

		result.resize(length);
		#pragma endregion

		#pragma region OffsetName
		result[0] = 0x14;
		#pragma endregion

		#pragma region ValueType
		result[4] = ((BYTE*)&ValueType)[0];
		result[5] = ((BYTE*)&ValueType)[1];
		#pragma endregion

		#pragma region Reserved
		result[6] = 0x00;
		result[7] = 0x00;
		#pragma endregion

		#pragma region Flags
		DWORD dword_flags = dword_vec((bin_t)*Flags);

		result[8] =  ((BYTE*)&dword_flags)[0];
		result[9] =  ((BYTE*)&dword_flags)[1];
		result[10] = ((BYTE*)&dword_flags)[2];
		result[11] = ((BYTE*)&dword_flags)[3];
		#pragma endregion

		#pragma region ValueCount
		DWORD ValueCount = Values.size();

		result[12] = ((BYTE*)&ValueCount)[0];
		result[13] = ((BYTE*)&ValueCount)[1];
		result[14] = ((BYTE*)&ValueCount)[2];
		result[15] = ((BYTE*)&ValueCount)[3];
		#pragma endregion

		#pragma region OffsetValues
		DWORD OffsetValues = 20 + ((Name.size() + 1) * sizeof(wchar_t));

		result[16] = ((BYTE*)&OffsetValues)[0];
		result[17] = ((BYTE*)&OffsetValues)[1];
		result[18] = ((BYTE*)&OffsetValues)[2];
		result[19] = ((BYTE*)&OffsetValues)[3];
		#pragma endregion

		#pragma region Name
		memcpy(result.data() + 20, &Name[0], Name.size() * sizeof(wchar_t));
		#pragma endregion

		#pragma region Values
		switch(ValueType)
		{
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
				for(auto&& element : Values)
				{
					auto get_if = std::get_if<LONG64>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					*((LONG64*)(result.data() + OffsetValues)) = (*get_if);
					OffsetValues += sizeof(LONG64);
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
				for(auto&& element : Values)
				{
					auto get_if = std::get_if<DWORD64>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					*((ULONG64*)(result.data() + OffsetValues)) = (*get_if);
					OffsetValues += sizeof(LONG64);
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
				for(auto&& element : Values)
				{
					auto get_if = std::get_if<std::shared_ptr<std::wstring>>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					memcpy(result.data() + OffsetValues, (*get_if)->data(), (*get_if)->size() * sizeof(wchar_t));
					OffsetValues += ((*get_if)->size() + 1) * sizeof(wchar_t);
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
				for(auto&& element : Values)
				{
					auto get_if = std::get_if<std::shared_ptr<XSID>>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					auto bin = (bin_t) * (*get_if);

					DWORD len = bin.size();
					memcpy(result.data() + OffsetValues, &len, sizeof(DWORD));
					OffsetValues += sizeof(DWORD);

					memcpy(result.data() + OffsetValues, bin.data(), bin.size());
					OffsetValues += bin.size();
				}

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
				for(auto&& element : Values)
				{
					auto get_if = std::get_if<std::shared_ptr<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>>(&element);
					if(nullptr == get_if)
						throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

					DWORD len = (*get_if)->Value.size();
					memcpy(result.data() + OffsetValues, &len, sizeof(DWORD));
					OffsetValues += sizeof(DWORD);

					memcpy(result.data() + OffsetValues, (*get_if)->Value.data(), (*get_if)->Value.size());
					OffsetValues += (*get_if)->Value.size();
				}

				break;
			default:
				throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect ValueType");
		}
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::XSECURITY_ATTRIBUTE_V1(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid input XML");
		#pragma endregion

		#pragma region Name
		msxml_et name = xml->selectSingleNode(L"Name");
		if(nullptr == name)
			throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot find 'Name' XML node");

		Name = (wchar_t*)name->text;
		#pragma endregion

		#pragma region ValueType
		msxml_et valueType = xml->selectSingleNode(L"ValueType");
		if(nullptr == valueType)
			throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot find 'ValueType' XML node");

		ValueType = _variant_t(valueType->text);
		#pragma endregion

		#pragma region Flags
		msxml_et flags = xml->selectSingleNode(L"Flags");
		if(nullptr == flags)
			throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot find 'Flags' XML node");

		Flags = std::make_shared<XBITSET<32>>(flags, SecurityAttributeV1Meaning);
		#pragma endregion

		#pragma region Values
		msxml_nt values = xml->selectNodes(L"Value");
		if(nullptr == values)
			throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot convert 'Value' XML node");

		Values.clear();

		switch(ValueType)
		{
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
				for(long i = 0; i < values->length; i++)
					Values.push_back(_variant_t(values->item[i]->text).operator long long());

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
				for(long i = 0; i < values->length; i++)
					Values.push_back(_variant_t(values->item[i]->text).operator unsigned long long());

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
				for(long i = 0; i < values->length; i++)
					Values.push_back(std::make_shared<std::wstring>((wchar_t*)values->item[i]->text));

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN:
				for(long i = 0; i < values->length; i++)
					Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_FQBN_VALUE>(values->item[i]));

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
				for(long i = 0; i < values->length; i++)
					Values.push_back(std::make_shared<XSID>(values->item[i]));

				break;
			case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
				for(long i = 0; i < values->length; i++)
					Values.push_back(std::make_shared<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>(values->item[i]));

				break;
			default:
				throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid ValueType");
		}
		#pragma endregion
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTE_V1::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et cattr = xml->createElement(std::wstring(root.value_or(L"XSECURITY_ATTRIBUTE_V1")).c_str());
			if(nullptr == cattr)
				throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot create root XML node");
			#pragma endregion

			#pragma region Name
			msxml_et name = xml->createElement(L"Name");
			if(nullptr == name)
				throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot create 'Name' XML node");

			name->appendChild(xml->createTextNode(Name.c_str()));

			cattr->appendChild(name);
			#pragma endregion

			#pragma region ValueType
			msxml_et valueType = xml->createElement(L"ValueType");
			if(nullptr == valueType)
				throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot create 'ValueType' XML node");

			valueType->appendChild(xml->createTextNode(_variant_t(ValueType).operator _bstr_t()));

			cattr->appendChild(valueType);
			#pragma endregion

			#pragma region Flags
			msxml_et flags = xml->createElement(L"Flags");
			if(nullptr == flags)
				throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot create 'Flags' XML node");

			cattr->appendChild(((xml_t)*Flags)(xml, L"Flags"));
			#pragma endregion

			#pragma region Values
			switch(ValueType)
			{
				case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
					for(auto&& element : Values)
					{
						auto get_if = std::get_if<LONG64>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						msxml_et value = xml->createElement(L"Value");
						if(nullptr == value)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot create 'Value' XML node");

						value->appendChild(xml->createTextNode(_variant_t(*get_if).operator _bstr_t()));

						cattr->appendChild(value);
					}

					break;
				case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
				case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
					for(auto&& element : Values)
					{
						auto get_if = std::get_if<DWORD64>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						msxml_et value = xml->createElement(L"Value");
						if(nullptr == value)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot create 'Value' XML node");

						value->appendChild(xml->createTextNode(_variant_t(*get_if).operator _bstr_t()));

						cattr->appendChild(value);
					}

					break;
				case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<std::wstring>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						msxml_et value = xml->createElement(L"Value");
						if(nullptr == value)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: cannot create 'Value' XML node");

						value->appendChild(xml->createTextNode((*get_if)->c_str()));

						cattr->appendChild(value);
					}

					break;
				case CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN:
					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<XSECURITY_ATTRIBUTE_FQBN_VALUE>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						cattr->appendChild(((xml_t)*(*get_if))(xml, L"Value"));
					}

					break;
				case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<XSID>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						cattr->appendChild(((xml_t)*(*get_if))(xml, L"Value"));
					}

					break;
				case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
					for(auto&& element : Values)
					{
						auto get_if = std::get_if<std::shared_ptr<XSECURITY_ATTRIBUTE_OCTET_STRING_VALUE>>(&element);
						if(nullptr == get_if)
							throw std::exception("XSECURITY_ATTRIBUTE_V1: incorrect combination of ValueType and Values");

						cattr->appendChild(((xml_t)*(*get_if))(xml, L"Value"));
					}

					break;
				default:
					throw std::exception("XSECURITY_ATTRIBUTE_V1: invalid ValueType");
			}
			#pragma endregion

			return cattr;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class working with XSECURITY_ATTRIBUTES_INFORMATION structure (XTOKEN and CLAIM)
	//****************************************************************************************
	struct XSECURITY_ATTRIBUTES_INFORMATION
	{
		XSECURITY_ATTRIBUTES_INFORMATION() = delete;
		~XSECURITY_ATTRIBUTES_INFORMATION() = default;

		XSECURITY_ATTRIBUTES_INFORMATION(const XSECURITY_ATTRIBUTES_INFORMATION& copy) : Version(copy.Version), Attributes(copy.Attributes)
		{}

		XSECURITY_ATTRIBUTES_INFORMATION(const std::initializer_list<XSECURITY_ATTRIBUTE_V1>&, const WORD& = 1);
		XSECURITY_ATTRIBUTES_INFORMATION(const std::vector<XSECURITY_ATTRIBUTE_V1>&, const WORD& = 1);

		XSECURITY_ATTRIBUTES_INFORMATION(const CLAIM_SECURITY_ATTRIBUTES_INFORMATION&);
		XSECURITY_ATTRIBUTES_INFORMATION(const TOKEN_SECURITY_ATTRIBUTES_INFORMATION&);
		XSECURITY_ATTRIBUTES_INFORMATION(const msxml_et&);

		explicit operator CLAIM_SECURITY_ATTRIBUTES_INFORMATION() const;
		explicit operator TOKEN_SECURITY_ATTRIBUTES_INFORMATION() const;
		explicit operator xml_t() const;

		WORD Version = 1;
		std::vector<std::shared_ptr<XSECURITY_ATTRIBUTE_V1>> Attributes;

		private:
		std::unique_ptr<bin_t> buffer_claim = std::make_unique<bin_t>();
		std::unique_ptr<bin_t> buffer_token = std::make_unique<bin_t>();
	};
	//****************************************************************************************
	XSECURITY_ATTRIBUTES_INFORMATION::XSECURITY_ATTRIBUTES_INFORMATION(const std::vector<XSECURITY_ATTRIBUTE_V1>& attributes, const WORD& version) : Version(version)
	{
		for(auto&& element : attributes)
			Attributes.push_back(std::make_shared<XSECURITY_ATTRIBUTE_V1>(element));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTES_INFORMATION::XSECURITY_ATTRIBUTES_INFORMATION(const std::initializer_list<XSECURITY_ATTRIBUTE_V1>& attributes, const WORD& version) : Version(version)
	{
		for(auto&& element : attributes)
			Attributes.push_back(std::make_shared<XSECURITY_ATTRIBUTE_V1>(element));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTES_INFORMATION::XSECURITY_ATTRIBUTES_INFORMATION(const CLAIM_SECURITY_ATTRIBUTES_INFORMATION& value)
	{
		Version = value.Version;

		Attributes.clear();

		for(DWORD i = 0; i < value.AttributeCount; i++)
			Attributes.push_back(std::make_shared<XSECURITY_ATTRIBUTE_V1>(value.Attribute.pAttributeV1[i]));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTES_INFORMATION::XSECURITY_ATTRIBUTES_INFORMATION(const TOKEN_SECURITY_ATTRIBUTES_INFORMATION& value)
	{
		Version = value.Version;

		Attributes.clear();

		for(DWORD i = 0; i < value.AttributeCount; i++)
			Attributes.push_back(std::make_shared<XSECURITY_ATTRIBUTE_V1>(value.Attribute.pAttributeV1[i]));
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTES_INFORMATION::XSECURITY_ATTRIBUTES_INFORMATION(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XSECURITY_ATTRIBUTES_INFORMATION: invalid input XML");
		#pragma endregion

		#pragma region Version
		msxml_et version = xml->selectSingleNode(L"Version");
		if(nullptr == version)
			throw std::exception("XSECURITY_ATTRIBUTES_INFORMATION: cannot find 'Version' XML node");

		Version = _variant_t(version->text);
		#pragma endregion

		#pragma region Attributes
		msxml_nt attributes = xml->selectNodes(L"Attribute");
		if(nullptr == attributes)
			throw std::exception("XSECURITY_ATTRIBUTES_INFORMATION: cannot find 'Attribute' XML node");

		for(long i = 0; i < attributes->length; i++)
			Attributes.push_back(std::make_shared<XSECURITY_ATTRIBUTE_V1>(attributes->item[i]));
		#pragma endregion
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTES_INFORMATION::operator CLAIM_SECURITY_ATTRIBUTES_INFORMATION() const
	{
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION result{};

		result.Version = Version;
		result.Reserved = 0;
		result.AttributeCount = Attributes.size();

		buffer_claim->resize(Attributes.size() * sizeof(CLAIM_SECURITY_ATTRIBUTE_V1));

		for(DWORD i = 0; i < result.AttributeCount; i++)
			((PCLAIM_SECURITY_ATTRIBUTE_V1)buffer_claim->data())[i] = (CLAIM_SECURITY_ATTRIBUTE_V1)*(Attributes[i]);

		result.Attribute.pAttributeV1 = (PCLAIM_SECURITY_ATTRIBUTE_V1)buffer_claim->data();

		return result;
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTES_INFORMATION::operator TOKEN_SECURITY_ATTRIBUTES_INFORMATION() const
	{
		TOKEN_SECURITY_ATTRIBUTES_INFORMATION result{};

		result.Version = Version;
		result.Reserved = 0;
		result.AttributeCount = Attributes.size();

		buffer_token->resize(Attributes.size() * sizeof(TOKEN_SECURITY_ATTRIBUTE_V1));

		for(DWORD i = 0; i < result.AttributeCount; i++)
			((PTOKEN_SECURITY_ATTRIBUTE_V1)buffer_token->data())[i] = (TOKEN_SECURITY_ATTRIBUTE_V1)*(Attributes[i]);

		result.Attribute.pAttributeV1 = (PTOKEN_SECURITY_ATTRIBUTE_V1)buffer_token->data();

		return result;
	}
	//****************************************************************************************
	XSECURITY_ATTRIBUTES_INFORMATION::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XSECURITY_ATTRIBUTES_INFORMATION: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et cattr = xml->createElement(std::wstring(root.value_or(L"XSECURITY_ATTRIBUTES_INFORMATION")).c_str());
			if(nullptr == cattr)
				throw std::exception("XSECURITY_ATTRIBUTES_INFORMATION: cannot create root XML node");
			#pragma endregion

			#pragma region Version
			msxml_et version = xml->createElement(L"Version");
			if(nullptr == version)
				throw std::exception("XSECURITY_ATTRIBUTES_INFORMATION: cannot create 'Version' XML node");

			version->appendChild(xml->createTextNode(_variant_t(Version).operator _bstr_t()));

			cattr->appendChild(version);
			#pragma endregion

			#pragma region Attributes
			for(auto&& element : Attributes)
				cattr->appendChild(((xml_t)*element)(xml, L"Attribute"));
			#pragma endregion

			return cattr;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
};
//********************************************************************************************
