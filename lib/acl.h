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
	struct XACL
	{
		XACL() = delete;
		~XACL() = default;

		XACL(const std::initializer_list<XACE>&);
		XACL(const std::vector<XACE>&);

		XACL(const unsigned char*, const dword_meaning_t& = DwordMeaningDefault);
		XACL(const bin_t&, const dword_meaning_t& = DwordMeaningDefault);
		XACL(const msxml_et&, const dword_meaning_t& = DwordMeaningDefault);

		explicit operator bin_t() const;
		explicit operator xml_t() const;

		// Values are pointers in order to be able to change them inside "const" functions
		std::shared_ptr<unsigned char> AclRevision = std::make_shared<unsigned char>(2);
		std::shared_ptr<WORD> AclSize = std::make_shared<WORD>(0);
		std::vector<std::shared_ptr<XACE>> AceArray;

		dword_meaning_t Meaning;

	private:
		void SetCorrectRevision() const
		{
			*AclRevision = 0x02;

			for(auto&& element : AceArray)
			{
				switch(element->AceData->Type)
				{
					case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
					case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
					case ACCESS_DENIED_OBJECT_ACE_TYPE:
					case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
					case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
					case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
					case SYSTEM_ALARM_OBJECT_ACE_TYPE:
					case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
						*AclRevision = 0x04;
						break;
					default:;
				}
			}
		}
	};
	//********************************************************************************************
	XACL::XACL(const std::initializer_list<XACE>& value) : XACL(std::vector<XACE>(value))
	{
	}
	//********************************************************************************************
	XACL::XACL(const std::vector<XACE>& aces) : Meaning(DwordMeaningDefault)
	{
		std::for_each(aces.begin(), aces.end(), [&](auto&& element) {
			AceArray.push_back(std::make_shared<XACE>(element));
			Meaning = element.AceData->Meaning;
		});

		SetCorrectRevision();
	}
	//********************************************************************************************
	XACL::XACL(const unsigned char* data, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region AclRevision
		*AclRevision = 0x02; // Hard-code correct value here
		#pragma endregion

		#pragma region AclSize
		WORD aclSize = 0;

		((BYTE*)&aclSize)[0] = data[2];
		((BYTE*)&aclSize)[1] = data[3];

		*AclSize = aclSize;
		#pragma endregion

		#pragma region AceCount
		size_t AceCount = 0;

		((BYTE*)&AceCount)[0] = data[4];
		((BYTE*)&AceCount)[1] = data[5];
		#pragma endregion

		#pragma region AceArray
		AceArray.clear();
		size_t start = 8;

		for(size_t i = 0; i < AceCount; i++)
		{
			auto ace = std::make_shared<XACE>(data + start, Meaning);
			start += ace->AceSize;

			AceArray.push_back(ace);
		}

		SetCorrectRevision();
		#pragma endregion
	}
	//********************************************************************************************
	XACL::XACL(const bin_t& data, const dword_meaning_t& meaning) : XACL((unsigned char*)data.data(), meaning)
	{
	}
	//********************************************************************************************
	XACL::operator bin_t() const
	{
		#pragma region Initial variables
		bin_t result;
		bin_t ace_array;
		#pragma endregion

		#pragma region AceArray
		for(std::shared_ptr<XACE> element : AceArray)
		{
			bin_t ace_bin = (bin_t)*element;
			std::copy(ace_bin.begin(), ace_bin.end(), std::back_inserter(ace_array));
		}
		#pragma endregion

		#pragma region Adjust AceSize
		#pragma warning(push)
		#pragma warning(disable: 4267)
		*AclSize = ace_array.size() + 8;
		#pragma warning(pop)
		#pragma endregion

		#pragma region Major data update
		SetCorrectRevision();

		result.push_back(*AclRevision);

		result.push_back(0x00); // Sbz1

		WORD aclSize = *AclSize;

		result.push_back(((BYTE*)&aclSize)[0]);
		result.push_back(((BYTE*)&aclSize)[1]);

		size_t AceCount = AceArray.size();
		result.push_back(((BYTE*)&AceCount)[0]);
		result.push_back(((BYTE*)&AceCount)[1]);

		result.push_back(0x00); // Sbz2
		result.push_back(0x00); // Sbz2

		std::copy(ace_array.begin(), ace_array.end(), std::back_inserter(result));
		#pragma endregion

		return result;
	}
	//********************************************************************************************
	XACL::XACL(const msxml_et& xml, const dword_meaning_t& meaning) : Meaning(meaning), AclSize(0)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("ACL: invalid input XML");
		#pragma endregion

		#pragma region AclRevision
		msxml_et aclRevision = xml->selectSingleNode(L"AclRevision");
		if(nullptr == aclRevision)
			throw std::exception("ACL: cannot find 'AclRevision' XML node");

		*AclRevision = _variant_t(aclRevision->text);
		#pragma endregion

		#pragma region AceArray
		msxml_nt aces = xml->selectNodes(L"ACE");
		if(nullptr == aces)
			throw std::exception("ACL: cannot find 'ACE' XML node");

		for(long i = 0; i < aces->length; i++)
			AceArray.push_back(std::make_shared<XACE>(aces->item[i], Meaning));

		SetCorrectRevision();
		#pragma endregion
	}
	//********************************************************************************************
	XACL::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("ACL: invalid output XML");
			#pragma endregion

			#pragma region Root element
			msxml_et acl = xml->createElement(std::wstring(root.value_or(L"ACL")).c_str());
			if(nullptr == acl)
				throw std::exception("ACL: cannot make root XML node");
			#pragma endregion

			#pragma region AclRevision
			msxml_et aclRevision = xml->createElement(L"AclRevision");
			if(nullptr == aclRevision)
				throw std::exception("ACL: cannot make 'AclRevision' XML node");

			SetCorrectRevision();

			aclRevision->appendChild(xml->createTextNode(_variant_t(*AclRevision).operator _bstr_t()));

			acl->appendChild(aclRevision);
			#pragma endregion

			#pragma region AceArray
			for(std::shared_ptr<XACE> element : AceArray)
				acl->appendChild(((xml_t)*element)(xml, std::nullopt));
			#pragma endregion

			return acl;
		};
	}
	//********************************************************************************************
};
//********************************************************************************************
