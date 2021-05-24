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
	#pragma region Major class for SECURITY_DESCRIPTOR data
	//********************************************************************************************
	struct XSD
	{
		XSD() = delete;
		~XSD() = default;

		// We need an explicit copy constructor because compiler does not know how to deal with "unique_ptr" private members
		XSD(const XSD& copy) : Revision(copy.Revision), Control(copy.Control), Owner(copy.Owner), Group(copy.Group), Sacl(copy.Sacl), Dacl(copy.Dacl), Meaning(copy.Meaning)
		{}

		XSD(
			const XSID& /*sid*/, 
			const std::optional<XACL>& /*dacl*/ = std::nullopt,
			const std::optional<XACL>& /*sacl*/ = std::nullopt,
			const XSID& /*group*/ = XSID::Everyone,
			const XBITSET<16>& /*control*/ = { (WORD)0, WordBitsMeaningSdControl }
		);


		XSD(const unsigned char*, const dword_meaning_t&);
		XSD(const bin_t&, const dword_meaning_t&);
		XSD(const msxml_et&, const dword_meaning_t&);

		explicit operator bin_t() const;
		explicit operator xml_t() const;

		void AppendSID(const XSID&, const DWORD&, const bool = false);

		static XSD GetFromKernelObject(const HANDLE&, const std::optional<XBITSET<32>> = std::nullopt, const dword_meaning_t& = DwordMeaningToken);
		static XSD GetFromFileObject(const std::wstring&, const std::optional<XBITSET<32>> = std::nullopt, const dword_meaning_t& = DwordMeaningFile);

		unsigned char Revision = 1;
		std::shared_ptr<XBITSET<16>> Control;

		std::shared_ptr<XSID> Owner;
		std::shared_ptr<XSID> Group;
		std::shared_ptr<XACL> Sacl;
		std::shared_ptr<XACL> Dacl;

		dword_meaning_t Meaning;

	private:
		// All is "shared_ptr" because we need to have "operator ... const"
		std::unique_ptr<bin_t> owner_bin = std::make_unique<bin_t>();
		std::unique_ptr<bin_t> group_bin = std::make_unique<bin_t>();
		std::unique_ptr<bin_t> sacl_bin = std::make_unique<bin_t>();
		std::unique_ptr<bin_t> dacl_bin = std::make_unique<bin_t>();
	};
	//********************************************************************************************
	XSD XSD::GetFromKernelObject(const HANDLE& handle, const std::optional<XBITSET<32>> _flags, const dword_meaning_t& meaning)
	{
		#pragma region Initial variables
		DWORD length = 0;
		DWORD flags = 0xFFFFFFFF;

		bool found = false;
		#pragma endregion

		#pragma region Find a maximum allowed security information to query
		if(_flags)
		{
			flags = (DWORD)_flags.value();

			BOOL result = GetKernelObjectSecurity(handle, flags--, nullptr, 0, &length);
			if((FALSE == result) && (ERROR_INSUFFICIENT_BUFFER == GetLastError()))
				found = true;
		}
		else
		{
			while(flags)
			{
				BOOL result = GetKernelObjectSecurity(handle, flags--, nullptr, 0, &length);
				if((FALSE == result) && (ERROR_INSUFFICIENT_BUFFER == GetLastError()))
				{
					found = true;
					break;
				}
			};
		}

		if(false == found)
			throw std::exception("XSD: cannot get security descriptor for the kernel object");
		#pragma endregion

		#pragma region Get and initialize security descriptor
		std::unique_ptr<SECURITY_DESCRIPTOR> sd{ static_cast<SECURITY_DESCRIPTOR*>(::operator new(length)) };

		BOOL result = GetKernelObjectSecurity(handle, ++flags, sd.get(), length, &length);
		if(FALSE == result)
			throw std::exception("XSD: cannot get security descriptor for the kernel object");

		return XSD((unsigned char*)sd.get(), meaning);
		#pragma endregion
	}
	//********************************************************************************************
	XSD XSD::GetFromFileObject(const std::wstring& path, const std::optional<XBITSET<32>> _flags, const dword_meaning_t& meaning)
	{
		#pragma region Initial variables
		DWORD length = 0;
		DWORD flags = 0xFFFFFFFF;

		bool found = false;
		#pragma endregion

		#pragma region Find a maximum allowed security information to query
		if(_flags)
		{
			flags = (DWORD)_flags.value();

			BOOL result = GetFileSecurity(path.c_str(), flags--, nullptr, 0, &length);
			if((FALSE == result) && (ERROR_INSUFFICIENT_BUFFER == GetLastError()))
				found = true;
		}
		else
		{
			while(flags)
			{
				BOOL result = GetFileSecurity(path.c_str(), flags--, nullptr, 0, &length);
				if((FALSE == result) && (ERROR_INSUFFICIENT_BUFFER == GetLastError()))
				{
					found = true;
					break;
				}
			};
		}

		if(false == found)
			throw std::exception("XSD: cannot get security descriptor for the file object");
		#pragma endregion

		#pragma region Get and initialize security descriptor
		std::unique_ptr<SECURITY_DESCRIPTOR> sd{ static_cast<SECURITY_DESCRIPTOR*>(::operator new(length)) };

		BOOL result = GetFileSecurity(path.c_str(), ++flags, sd.get(), length, &length);
		if(FALSE == result)
			throw std::exception("XSD: cannot get security descriptor for the file object");
		#pragma endregion

		return XSD((unsigned char*)sd.get(), meaning);
	}
	//********************************************************************************************
	XSD::XSD(const unsigned char* data, const dword_meaning_t& meaning)
	{
		#pragma region Revision
		Revision = data[0];
		#pragma endregion

		#pragma region Control
		Control = std::make_shared<XBITSET<16>>(data + 2, WordBitsMeaningSdControl);
		#pragma endregion

		#pragma region Get remaining data from "self-relative" or "absolute" forms of XSD
		#pragma region Self-relative form of security descriptor
		if(Control->get(L"SE_SELF_RELATIVE"))
		{
			#pragma region Owner
			DWORD OffsetOwner = 0;
			((BYTE*)&OffsetOwner)[0] = data[4];
			((BYTE*)&OffsetOwner)[1] = data[5];
			((BYTE*)&OffsetOwner)[2] = data[6];
			((BYTE*)&OffsetOwner)[3] = data[7];

			if(OffsetOwner)
				Owner = std::make_shared<XSID>(data + OffsetOwner);
			#pragma endregion

			#pragma region Group
			DWORD OffsetGroup = 0;
			((BYTE*)&OffsetGroup)[0] = data[8];
			((BYTE*)&OffsetGroup)[1] = data[9];
			((BYTE*)&OffsetGroup)[2] = data[10];
			((BYTE*)&OffsetGroup)[3] = data[11];

			if(OffsetGroup)
				Group = std::make_shared<XSID>(data + OffsetGroup);
			#pragma endregion

			#pragma region Sacl
			DWORD OffsetSacl = 0;
			((BYTE*)&OffsetSacl)[0] = data[12];
			((BYTE*)&OffsetSacl)[1] = data[13];
			((BYTE*)&OffsetSacl)[2] = data[14];
			((BYTE*)&OffsetSacl)[3] = data[15];

			if(OffsetSacl)
				Sacl = std::make_shared<XACL>(data + OffsetSacl, meaning);
			#pragma endregion

			#pragma region Dacl
			DWORD OffsetDacl = 0;
			((BYTE*)&OffsetDacl)[0] = data[16];
			((BYTE*)&OffsetDacl)[1] = data[17];
			((BYTE*)&OffsetDacl)[2] = data[18];
			((BYTE*)&OffsetDacl)[3] = data[19];

			if(OffsetDacl)
				Dacl = std::make_shared<XACL>(data + OffsetDacl, meaning);
			#pragma endregion
		}
		#pragma endregion
		#pragma region Absolute form of security descriptor
		else
		{
			#pragma region Owner
			BYTE* ownerData = nullptr;
			memcpy(&ownerData, data + 4, 4);

			if(nullptr != ownerData)
				Owner = std::make_shared<XSID>(ownerData);
			#pragma endregion

			#pragma region Group
			BYTE* groupData = nullptr;
			memcpy(&groupData, data + 8, 4);

			if(nullptr != groupData)
				Group = std::make_shared<XSID>(groupData);
			#pragma endregion

			#pragma region Sacl
			BYTE* saclData = nullptr;
			memcpy(&saclData, data + 12, 4);

			if(nullptr != saclData)
				Sacl = std::make_shared<XACL>(saclData, meaning);
			#pragma endregion

			#pragma region Dacl
			BYTE* daclData = nullptr;
			memcpy(&daclData, data + 16, 4);

			if(nullptr != daclData)
				Dacl = std::make_shared<XACL>(daclData, meaning);
		}
		#pragma endregion
		#pragma endregion
	}
	//********************************************************************************************
	XSD::XSD(
		const XSID& owner,
		const std::optional<XACL>& dacl,
		const std::optional<XACL>& sacl,
		const XSID& group,
		const XBITSET<16>& control
	)
	{	
		Owner = std::make_shared<XSID>(owner);
		Group = std::make_shared<XSID>(group);

		Control = std::make_shared<XBITSET<16>>(control);

		Control->set((size_t)2, false); // SE_DACL_PRESENT
		Control->set((size_t)4, false); // SE_SACL_PRESENT

		Meaning = DwordMeaningDefault;

		if(sacl)
		{
			Sacl = std::make_shared<XACL>(sacl.value());

			Meaning = sacl->Meaning;
			Control->set((size_t)4, true); // SE_SACL_PRESENT
		}

		if(dacl)
		{
			Dacl = std::make_shared<XACL>(dacl.value());

			Meaning = dacl->Meaning;
			Control->set((size_t)2, true); // SE_DACL_PRESENT
		}
	}
	//********************************************************************************************
	XSD::XSD(const bin_t& data, const dword_meaning_t& meaning) : XSD(data.data(), meaning)
	{
	}
	//********************************************************************************************
	XSD::operator bin_t() const
	{
		#pragma region Initial check
		if(nullptr == Control)
			throw std::exception("XSD: initialize data first");
		#pragma endregion

		#pragma region Owner
		if(nullptr != Owner)
			*owner_bin = (bin_t)*Owner;
		#pragma endregion

		#pragma region Group
		if(nullptr != Group)
			*group_bin = (bin_t)*Group;
		#pragma endregion

		#pragma region Sacl
		if(nullptr != Sacl)
		{
			*sacl_bin = (bin_t)*Sacl;
			Control->set((size_t)4, true); // SE_SACL_PRESENT
		}
		#pragma endregion

		#pragma region Dacl
		if(nullptr != Dacl)
		{
			*dacl_bin = (bin_t)*Dacl;
			Control->set((size_t)2, true); // SE_DACL_PRESENT
		}
		#pragma endregion

		#pragma region Control
		bin_t control_bin = (bin_t)*Control;
		#pragma endregion

		#pragma region Allocate output data
		size_t length = 20;

		if(Control->get((size_t)15)) // SE_SELF_RELATIVE
			length = 20 + owner_bin->size() + group_bin->size() + sacl_bin->size() + dacl_bin->size();

		bin_t result(length);
		#pragma endregion

		#pragma region Create security descriptor header
		//result[0] = Revision;
		result[0] = 0x01; // Should be always set to 1
		result[1] = 0x00; // Sbz1

		result[2] = control_bin[0];
		result[3] = control_bin[1];
		#pragma endregion

		#pragma region Create security descriptor data
		#pragma region Append data to "self-relative" security descriptor
		if(Control->get((size_t)15)) // SE_SELF_RELATIVE
		{
			#pragma region Owner
			if(owner_bin->size())
			{
				DWORD OffsetOwner = 20;

				result[4] = ((BYTE*)&OffsetOwner)[0];
				result[5] = ((BYTE*)&OffsetOwner)[1];
				result[6] = ((BYTE*)&OffsetOwner)[2];
				result[7] = ((BYTE*)&OffsetOwner)[3];

				for(unsigned char element : *owner_bin)
					result[OffsetOwner++] = element;
			}
			#pragma endregion

			#pragma region Group
			if(group_bin->size())
			{
				DWORD OffsetGroup = 20 + owner_bin->size();

				result[8] = ((BYTE*)&OffsetGroup)[0];
				result[9] = ((BYTE*)&OffsetGroup)[1];
				result[10] = ((BYTE*)&OffsetGroup)[2];
				result[11] = ((BYTE*)&OffsetGroup)[3];

				for(unsigned char element : *group_bin)
					result[OffsetGroup++] = element;
			}
			#pragma endregion

			#pragma region Sacl
			if(sacl_bin->size())
			{
				DWORD OffsetSacl = 20 + owner_bin->size() + group_bin->size();

				result[12] = ((BYTE*)&OffsetSacl)[0];
				result[13] = ((BYTE*)&OffsetSacl)[1];
				result[14] = ((BYTE*)&OffsetSacl)[2];
				result[15] = ((BYTE*)&OffsetSacl)[3];

				for(unsigned char element : *sacl_bin)
					result[OffsetSacl++] = element;
			}
			#pragma endregion

			#pragma region Dacl
			if(dacl_bin->size())
			{
				DWORD OffsetDacl = 20 + owner_bin->size() + group_bin->size() + sacl_bin->size();

				result[16] = ((BYTE*)&OffsetDacl)[0];
				result[17] = ((BYTE*)&OffsetDacl)[1];
				result[18] = ((BYTE*)&OffsetDacl)[2];
				result[19] = ((BYTE*)&OffsetDacl)[3];

				for(unsigned char element : *dacl_bin)
					result[OffsetDacl++] = element;
			}
			#pragma endregion
		}
		#pragma endregion
		#pragma region Append data to "absolute" security descriptor
		else
		{
			if(owner_bin->size())
			{
				BYTE* owner_data = owner_bin->data();
				memcpy(result.data() + 4, &owner_data, 4);
			}

			if(group_bin->size())
			{
				BYTE* group_data = group_bin->data();
				memcpy(result.data() + 8, &group_data, 4);
			}

			if(sacl_bin->size())
			{
				BYTE* sacl_data = sacl_bin->data();
				memcpy(result.data() + 12, &sacl_data, 4);
			}

			if(dacl_bin->size())
			{
				BYTE* dacl_data = dacl_bin->data();
				memcpy(result.data() + 16, &dacl_data, 4);
			}
		}
		#pragma endregion
		#pragma endregion

		return result;
	}
	//********************************************************************************************
	XSD::XSD(const msxml_et& xml, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XSD: invalid input XML");
		#pragma endregion

		#pragma region Revision
		msxml_et revision = xml->selectSingleNode(L"Revision");
		if(nullptr == revision)
			throw std::exception("XSD: cannot find 'Revision' XML node");

		Revision = _variant_t(revision->text);
		#pragma endregion

		#pragma region Control
		msxml_et control = xml->selectSingleNode(L"Control");
		if(nullptr == control)
			throw std::exception("XSD: cannot find 'Control' XML node");

		Control = std::make_shared<XBITSET<16>>(control, WordBitsMeaningSdControl);
		#pragma endregion

		#pragma region Owner
		msxml_et owner = xml->selectSingleNode(L"Owner");
		if(nullptr != owner)
			Owner = std::make_shared<XSID>(owner);
		#pragma endregion

		#pragma region Group
		msxml_et group = xml->selectSingleNode(L"Group");
		if(nullptr != group)
			Group = std::make_shared<XSID>(group);
		#pragma endregion

		#pragma region Sacl
		msxml_et sacl = xml->selectSingleNode(L"Sacl");
		if(nullptr != sacl)
			Sacl = std::make_shared<XACL>(sacl, Meaning);
		#pragma endregion

		#pragma region Dacl
		msxml_et dacl = xml->selectSingleNode(L"Dacl");
		if(nullptr != dacl)
			Dacl = std::make_shared<XACL>(dacl, Meaning);
		#pragma endregion
	}
	//********************************************************************************************
	XSD::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XSD: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et sd = xml->createElement(std::wstring(root.value_or(L"SecurityDescriptor")).c_str());
			if(nullptr == sd)
				throw std::exception("XSD: cannot create root XML element");
			#pragma endregion

			#pragma region Revision
			msxml_et revision = xml->createElement(L"Revision");
			if(nullptr == revision)
				throw std::exception("XSD: cannot create 'Revision' XML element");

			revision->appendChild(xml->createTextNode(_variant_t(Revision).operator _bstr_t()));
			sd->appendChild(revision);
			#pragma endregion

			#pragma region Control
			if(nullptr == Control)
				throw std::exception("XSD: initialize data first");

			sd->appendChild(((xml_t)*Control)(xml, L"Control"));
			#pragma endregion

			#pragma region Owner
			if(nullptr != Owner)
				sd->appendChild(((xml_t)*Owner)(xml, L"Owner"));
			#pragma endregion

			#pragma region Group
			if(nullptr != Group)
				sd->appendChild(((xml_t)*Group)(xml, L"Group"));
			#pragma endregion

			#pragma region Sacl
			if(nullptr != Sacl)
				sd->appendChild(((xml_t)*Sacl)(xml, L"Sacl"));
			#pragma endregion

			#pragma region Dacl
			if(nullptr != Dacl)
				sd->appendChild(((xml_t)*Dacl)(xml, L"Dacl"));
			#pragma endregion

			return sd;
		};
	}
	//********************************************************************************************
	void XSD::AppendSID(const XSID& sid, const DWORD& access, const bool denied)
	{
		#pragma region Create new DACL if needed
		if(nullptr == Dacl)
			Dacl = std::make_shared<XACL>(std::initializer_list<XACE>{});
		#pragma endregion

		#pragma region Find a place where insert new ACE
		size_t put_at = 0;

		if(!denied)
		{
			for(auto&& element : Dacl->AceArray)
			{
				// An "allow" ACE must be after all "denied" ACEs
				if((ACCESS_DENIED_ACE_TYPE == element->AceData->Type) ||
					(ACCESS_DENIED_OBJECT_ACE_TYPE == element->AceData->Type) ||
					(ACCESS_DENIED_CALLBACK_ACE_TYPE == element->AceData->Type) ||
					(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE == element->AceData->Type))
				{
					put_at++;
					continue;
				}

				break;
			}
		}
		#pragma endregion

		#pragma region Insert new ACE
		Dacl->AceArray.insert(
			Dacl->AceArray.begin() + put_at, 
			std::make_shared<XACE>(
				XACE_TYPE1(
					(unsigned char)((denied) ? ACCESS_DENIED_ACE_TYPE : ACCESS_ALLOWED_ACE_TYPE),
					sid,
					{ access, Meaning }
				)
			)
		);
		#pragma endregion
	}
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
}
//********************************************************************************************

