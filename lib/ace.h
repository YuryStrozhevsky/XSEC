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
	#pragma region ACE type names
	//********************************************************************************************
	const std::wstring typeNames[]{
		L"ACCESS_ALLOWED_ACE_TYPE",
		L"ACCESS_DENIED_ACE_TYPE",
		L"SYSTEM_AUDIT_ACE_TYPE",
		L"SYSTEM_ALARM_ACE_TYPE",
		L"ACCESS_ALLOWED_COMPOUND_ACE_TYPE",
		L"ACCESS_ALLOWED_OBJECT_ACE_TYPE",
		L"ACCESS_DENIED_OBJECT_ACE_TYPE",
		L"SYSTEM_AUDIT_OBJECT_ACE_TYPE",
		L"SYSTEM_ALARM_OBJECT_ACE_TYPE",
		L"ACCESS_ALLOWED_CALLBACK_ACE_TYPE",
		L"ACCESS_DENIED_CALLBACK_ACE_TYPE",
		L"ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE",
		L"ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE",
		L"SYSTEM_AUDIT_CALLBACK_ACE_TYPE",
		L"SYSTEM_ALARM_CALLBACK_ACE_TYPE",
		L"SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE",
		L"SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE",
		L"SYSTEM_MANDATORY_LABEL_ACE_TYPE",
		L"SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE",
		L"SYSTEM_SCOPED_POLICY_ID_ACE_TYPE",
		L"SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE",
		L"SYSTEM_ACCESS_FILTER_ACE_TYPE",
	};
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
	#pragma region Basic class for all ACE types
	//********************************************************************************************
	struct XACE_TYPE
	{
		XACE_TYPE() = delete;
		virtual ~XACE_TYPE() = default;

		XACE_TYPE(const unsigned char, const dword_meaning_t&);

		virtual explicit operator bin_t() const = 0;
		virtual explicit operator xml_t() const = 0;

		unsigned char Type = 0;
		dword_meaning_t Meaning = DwordMeaningDefault;
	};
	//********************************************************************************************
	XACE_TYPE::XACE_TYPE(const unsigned char type, const dword_meaning_t& meaning) : Meaning(meaning), Type(type)
	{
	}
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
	#pragma region Class for XACE_TYPE1
	//********************************************************************************************
	struct XACE_TYPE1 : public XACE_TYPE
	{
		/// <summary>Class for:
		///  <para>+ ACCESS_ALLOWED_ACE_TYPE</para>
		///  <para>+ ACCESS_DENIED_ACE_TYPE</para>
		///  <para>+ SYSTEM_AUDIT_ACE_TYPE</para>
		///  <para>+ SYSTEM_MANDATORY_LABEL_ACE_TYPE</para>
		///  <para>+ SYSTEM_SCOPED_POLICY_ID_ACE_TYPE</para>
		/// </summary>

		XACE_TYPE1() = delete;
		~XACE_TYPE1() = default;

		XACE_TYPE1(const unsigned char&, const XSID&, const XBITSET<32> & = { (DWORD)0, DwordMeaningDefault });

		XACE_TYPE1(const bin_t&, const unsigned char, const dword_meaning_t&);
		XACE_TYPE1(const msxml_et&, const unsigned char, const dword_meaning_t&);

		explicit operator bin_t() const;
		explicit operator xml_t() const;

		std::shared_ptr<XBITSET<32>> Mask;
		std::shared_ptr<XSID> Sid;

		private:
		void CheckType()
		{
			switch(Type)
			{
				case ACCESS_ALLOWED_ACE_TYPE:
				case ACCESS_DENIED_ACE_TYPE:
				case SYSTEM_AUDIT_ACE_TYPE:
				case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
				case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
					break;
				default:
					throw std::exception("XACE_TYPE1: incorrect type");
			}
		}
	};
	//********************************************************************************************
	XACE_TYPE1::XACE_TYPE1(const unsigned char& type, const XSID& sid, const XBITSET<32>& mask) : XACE_TYPE(type, mask.Meaning)
	{
		CheckType();

		Mask = std::make_shared<XBITSET<32>>(mask);
		Sid = std::make_shared<XSID>(sid);
	}
	//********************************************************************************************
	XACE_TYPE1::XACE_TYPE1(const bin_t& data, const unsigned char type, const dword_meaning_t& meaning) : XACE_TYPE(type, meaning)
	{
		#pragma region Check for a correct input type
		CheckType();
		#pragma endregion

		Mask = std::make_shared<XBITSET<32>>(bin_t(data.begin(), data.begin() + 4), Meaning);
		Sid = std::make_shared<XSID>(bin_t(data.begin() + 4, data.end()));
	}
	//********************************************************************************************
	XACE_TYPE1::operator bin_t() const
	{
		#pragma region Initial variables
		bin_t result;
		#pragma endregion

		#pragma region Additional check
		if((nullptr == Sid) || (nullptr == Mask))
			throw std::exception("XACE_TYPE1: initialize data first");
		#pragma endregion

		#pragma region Mask
		auto MaskData = (bin_t)*Mask;
		std::copy(MaskData.begin(), MaskData.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region Sid
		auto SidData = (bin_t)*Sid;
		std::copy(SidData.begin(), SidData.end(), std::back_inserter(result));
		#pragma endregion

		return result;
	}
	//********************************************************************************************
	XACE_TYPE1::XACE_TYPE1(const msxml_et& xml, const unsigned char type, const dword_meaning_t& meaning) : XACE_TYPE(type, meaning)
	{
		#pragma region Check for a correct input type
		CheckType();
		#pragma endregion

		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XACE_TYPE1: invalid input XML");
		#pragma endregion

		#pragma region Mask
		msxml_et mask = xml->selectSingleNode(L"AccessMask");
		if(nullptr == mask)
			throw std::exception("XACE_TYPE1: cannot find 'AccessMask' XML node");

		Mask = std::make_shared<XBITSET<32>>(mask, Meaning);
		#pragma endregion

		#pragma region Sid
		msxml_et sid = xml->selectSingleNode(L"SID");
		if(nullptr == sid)
			throw std::exception("XACE_TYPE1: cannot find 'SID' XML node");

		Sid = std::make_shared<XSID>(sid);
		#pragma endregion
	}
	//********************************************************************************************
	XACE_TYPE1::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XACE_TYPE1: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et aceData = xml->createElement(std::wstring(root.value_or(L"AceData")).c_str());
			if(nullptr == aceData)
				throw std::exception("XACE_TYPE1: cannot make root XML");
			#pragma endregion

			#pragma region Mask
			if(nullptr == Mask)
				throw std::exception("XACE_TYPE1: initialize data first");

			aceData->appendChild(((xml_t)*Mask)(xml, L"AccessMask"));
			#pragma endregion

			#pragma region Sid
			if(nullptr == Sid)
				throw std::exception("XACE_TYPE1: initialize data first");

			aceData->appendChild(((xml_t)*Sid)(xml, L"SID"));
			#pragma endregion

			return aceData;
		};
	}
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
	#pragma region Class for XACE_TYPE2
	//********************************************************************************************
	struct XACE_TYPE2 : public XACE_TYPE
	{
		/// <summary>Class for:
		///  <para>+ ACCESS_ALLOWED_OBJECT_ACE_TYPE</para>
		///  <para>+ ACCESS_DENIED_OBJECT_ACE_TYPE</para>
		/// </summary>

		XACE_TYPE2() = delete;
		~XACE_TYPE2() = default;

		XACE_TYPE2(
			const unsigned char& /*type*/,
			const XSID& /*Sid*/,
			const XBITSET<32>& /*Mask*/ = { (DWORD)0, DwordMeaningDefault },
			const std::optional<XGUID>& /*ObjectType*/ = std::nullopt,
			const std::optional<XGUID>& /*InheritedObjectType*/ = std::nullopt,
			const XBITSET<32> & /*Flags*/ = { (DWORD)0, DwordMeaningAceType2Flags }
		);

		XACE_TYPE2(const bin_t&, const unsigned char, const dword_meaning_t&);
		XACE_TYPE2(const msxml_et&, const unsigned char, const dword_meaning_t&);

		explicit operator bin_t() const;
		explicit operator xml_t() const;

		std::shared_ptr<XBITSET<32>> Mask;
		std::shared_ptr<XBITSET<32>> Flags;
		std::shared_ptr<XGUID> ObjectType;
		std::shared_ptr<XGUID> InheritedObjectType;
		std::shared_ptr<XSID> Sid;

		private:
		void CheckType()
		{
			switch(Type)
			{
				case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
				case ACCESS_DENIED_OBJECT_ACE_TYPE:
					break;
				default:
					throw std::exception("XACE_TYPE2: incorrect ACE type");
			}
		}
	};
	//********************************************************************************************
	XACE_TYPE2::XACE_TYPE2(
		const unsigned char& type,
		const XSID& sid,
		const XBITSET<32>& mask,
		const std::optional<XGUID>& objectType,
		const std::optional<XGUID>& inheritedObjectType,
		const XBITSET<32>& flags
	) : XACE_TYPE(type, mask.Meaning)
	{
		CheckType();

		Mask = std::make_shared<XBITSET<32>>(mask);
		Flags = std::make_shared<XBITSET<32>>(flags);

		Flags->set((size_t)0, false);
		Flags->set((size_t)1, false);

		if(objectType)
		{
			Flags->set((size_t)0, true);
			ObjectType = std::make_shared<XGUID>(objectType.value());
		}

		if(inheritedObjectType)
		{
			Flags->set((size_t)1, true);
			InheritedObjectType = std::make_shared<XGUID>(inheritedObjectType.value());
		}

		Sid = std::make_shared<XSID>(sid);
	}
	//********************************************************************************************
	XACE_TYPE2::XACE_TYPE2(const bin_t& data, const unsigned char type, const dword_meaning_t& meaning) : XACE_TYPE(type, meaning)
	{
		#pragma region Check for a correct input type
		CheckType();
		#pragma endregion

		#pragma region Intial variables
		size_t start = 8;
		#pragma endregion

		#pragma region Basic values
		Mask = std::make_shared<XBITSET<32>>(bin_t(data.begin(), data.begin() + 4), Meaning);
		Flags = std::make_shared<XBITSET<32>>(bin_t(data.begin() + 4, data.begin() + 8), DwordMeaningAceType2Flags);
		#pragma endregion

		#pragma region ObjectType
		if(Flags->get(L"ACE_OBJECT_TYPE_PRESENT"))
		{
			ObjectType = std::make_shared<XGUID>(bin_t{ data.begin() + 8, data.begin() + 24 });
			start += 16;
		}
		#pragma endregion

		#pragma region InheritedObjectType
		if(Flags->get(L"ACE_INHERITED_OBJECT_TYPE_PRESENT"))
		{
			InheritedObjectType = std::make_shared<XGUID>(bin_t{ data.begin() + start, data.begin() + start + 16 });
			start += 16;
		}
		#pragma endregion

		#pragma region Sid
		Sid = std::make_shared<XSID>(bin_t(data.begin() + start, data.end()));
		#pragma endregion
	}
	//********************************************************************************************
	XACE_TYPE2::XACE_TYPE2(const msxml_et& xml, const unsigned char type, const dword_meaning_t& meaning) : XACE_TYPE(type, meaning)
	{
		#pragma region Check for a correct input type
		CheckType();
		#pragma endregion

		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XACE_TYPE2: invalid input XML");
		#pragma endregion

		#pragma region Mask
		msxml_et mask = xml->selectSingleNode(L"AccessMask");
		if(nullptr == mask)
			throw std::exception("XACE_TYPE2: cannot find 'AccessMask' XML node");

		Mask = std::make_shared<XBITSET<32>>(mask, Meaning);
		#pragma endregion

		#pragma region Flags
		msxml_et flags = xml->selectSingleNode(L"Flags");
		if(nullptr != flags)
			Flags = std::make_shared<XBITSET<32>>(flags, DwordMeaningAceType2Flags);
		else
			Flags = std::make_shared<XBITSET<32>>(bin_t{ 0x00, 0x00, 0x00, 0x00 }, DwordMeaningAceType2Flags);
		#pragma endregion

		#pragma region ObjectType
		msxml_et objectType = xml->selectSingleNode(L"ObjectType");
		if(nullptr != objectType)
		{
			ObjectType = std::make_shared<XGUID>(objectType);
			Flags->set(L"ACE_OBJECT_TYPE_PRESENT", true);
		}
		#pragma endregion

		#pragma region InheritedObjectType
		msxml_et inheritedObjectType = xml->selectSingleNode(L"InheritedObjectType");
		if(nullptr != inheritedObjectType)
		{
			InheritedObjectType = std::make_shared<XGUID>(inheritedObjectType);
			Flags->set(L"ACE_INHERITED_OBJECT_TYPE_PRESENT", true);
		}
		#pragma endregion

		#pragma region Sid
		msxml_et sid = xml->selectSingleNode(L"SID");
		if(nullptr == sid)
			throw std::exception("XACE_TYPE2: cannot find 'SID' XML node");

		Sid = std::make_shared<XSID>(sid);
		#pragma endregion
	}
	//********************************************************************************************
	XACE_TYPE2::operator bin_t() const
	{
		#pragma region Additional check
		if((nullptr == Sid) || (nullptr == Mask))
			throw std::exception("XACE_TYPE2: initialize data first");
		#pragma endregion

		#pragma region Initial variables
		bin_t result;
		#pragma endregion

		#pragma region Mask
		auto MaskData = (bin_t)*Mask;
		std::copy(MaskData.begin(), MaskData.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region Flags
		Flags->set(L"ACE_OBJECT_TYPE_PRESENT", nullptr != ObjectType);
		Flags->set(L"ACE_INHERITED_OBJECT_TYPE_PRESENT", nullptr != InheritedObjectType);

		auto FlagsData = (bin_t)*Flags;
		std::copy(FlagsData.begin(), FlagsData.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region ObjectType
		if(nullptr != ObjectType)
		{
			auto bin = (bin_t)*ObjectType;
			std::copy(bin.begin(), bin.end(), std::back_inserter(result));
		}
		#pragma endregion

		#pragma region InheritedObjectType                                                                               
		if(nullptr != InheritedObjectType)
		{
			auto bin = (bin_t)*InheritedObjectType;
			std::copy(bin.begin(), bin.end(), std::back_inserter(result));
		}
		#pragma endregion

		#pragma region Sid
		auto SidData = (bin_t)*Sid;
		std::copy(SidData.begin(), SidData.end(), std::back_inserter(result));
		#pragma endregion

		return result;
	}
	//********************************************************************************************
	XACE_TYPE2::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XACE_TYPE2: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et aceData = xml->createElement(std::wstring(root.value_or(L"AceData")).c_str());
			if(nullptr == aceData)
				throw std::exception("XACE_TYPE2: cannot make root XML");
			#pragma endregion

			#pragma region Mask
			if(nullptr == Mask)
				throw std::exception("XACE_TYPE2: initialize data first");

			aceData->appendChild(((xml_t)*Mask)(xml, L"AccessMask"));
			#pragma endregion

			#pragma region Flags
			if(nullptr == Flags)
				throw std::exception("XACE_TYPE2: initialize data first");

			aceData->appendChild(((xml_t)*Flags)(xml, L"Flags"));
			#pragma endregion

			#pragma region ObjectType
			if(nullptr != ObjectType)
				aceData->appendChild(((xml_t)*ObjectType)(xml, L"ObjectType"));
			#pragma endregion

			#pragma region InheritedObjectType
			if(nullptr != InheritedObjectType)
				aceData->appendChild(((xml_t)*InheritedObjectType)(xml, L"InheritedObjectType"));
			#pragma endregion

			#pragma region Sid
			if(nullptr == Sid)
				throw std::exception("XACE_TYPE2: initialize data first");

			aceData->appendChild(((xml_t)*Sid)(xml, L"SID"));
			#pragma endregion

			return aceData;
		};
	}
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
	#pragma region Class for XACE_TYPE3
	//********************************************************************************************
	struct XACE_TYPE3 : public XACE_TYPE
	{
		/// <summary>Class for:
		///  <para>+ ACCESS_ALLOWED_CALLBACK_OBJECT_ACE</para>
		///  <para>+ ACCESS_DENIED_CALLBACK_OBJECT_ACE</para>
		///  <para>+ SYSTEM_AUDIT_CALLBACK_OBJECT_ACE</para>
		///  <para>+ SYSTEM_AUDIT_OBJECT_ACE_TYPE</para>
		/// </summary>

		XACE_TYPE3() = delete;
		~XACE_TYPE3() = default;

		XACE_TYPE3(
			const unsigned char& /*type*/,
			const XSID& /*Sid*/,
			const XBITSET<32>& /*Mask*/ = { (DWORD)0, DwordMeaningDefault },
			const std::optional<XCONDITIONAL_EXPRESSION> & /*ConditionalExpression*/ = std::nullopt,
			const std::optional<XGUID>& /*ObjectType*/ = std::nullopt,
			const std::optional<XGUID>& /*InheritedObjectType*/ = std::nullopt,
			const std::optional<bin_t>& /*ApplicationData*/ = std::nullopt,
			const XBITSET<32> & /*Flags*/ = { (DWORD)0, DwordMeaningAceType2Flags }
		);

		XACE_TYPE3(const bin_t&, const unsigned char, const dword_meaning_t&);
		XACE_TYPE3(const msxml_et&, const unsigned char, const dword_meaning_t&);

		explicit operator bin_t() const;
		explicit operator xml_t() const;

		std::shared_ptr<XBITSET<32>> Mask;
		std::shared_ptr<XBITSET<32>> Flags;
		std::shared_ptr<XGUID> ObjectType;
		std::shared_ptr<XGUID> InheritedObjectType;
		std::shared_ptr<XSID> Sid;
		std::shared_ptr<bin_t> ApplicationData;

		std::shared_ptr<XCONDITIONAL_EXPRESSION> ConditionalExpression; // The property does not exists on SYSTEM_AUDIT_OBJECT_ACE_TYPE

	private:
		void CheckType()
		{
			switch(Type)
			{
				case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
				case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
				case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
				case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
					break;
				default:
					throw std::exception("XACE_TYPE3: incorrect ACE type");
			}
		}
	};
	//********************************************************************************************
	XACE_TYPE3::XACE_TYPE3(
		const unsigned char& type,
		const XSID& sid,
		const XBITSET<32>& mask,
		const std::optional<XCONDITIONAL_EXPRESSION>& conditionalExpression,
		const std::optional<XGUID>& objectType,
		const std::optional<XGUID>& inheritedObjectType,
		const std::optional<bin_t>& applicationData,
		const XBITSET<32>& flags
	) : XACE_TYPE(type, mask.Meaning)
	{
		CheckType();

		Sid = std::make_shared<XSID>(sid);

		Mask = std::make_shared<XBITSET<32>>(mask);
		Flags = std::make_shared<XBITSET<32>>(flags);

		Flags->set((size_t)0, false);
		Flags->set((size_t)1, false);

		if(objectType)
		{
			Flags->set((size_t)0, true);
			ObjectType = std::make_shared<XGUID>(objectType.value());
		}

		if(inheritedObjectType)
		{
			Flags->set((size_t)1, true);
			InheritedObjectType = std::make_shared<XGUID>(inheritedObjectType.value());
		}

		if(applicationData)
			ApplicationData = std::make_shared<bin_t>(applicationData.value());

		switch(Type)
		{
			case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
			case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
			case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
				if(!conditionalExpression && applicationData)
					ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(*ApplicationData);
				else
				{
					if(conditionalExpression)
					{
						ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(conditionalExpression.value());
						ApplicationData = std::make_shared<bin_t>((bin_t)*ConditionalExpression);
					}
				}

				break;
			default:;
		}
	}
	//********************************************************************************************
	XACE_TYPE3::XACE_TYPE3(const bin_t& data, const unsigned char type, const dword_meaning_t& meaning) : XACE_TYPE(type, meaning)
	{
		#pragma region Check for a correct input type
		CheckType();
		#pragma endregion

		#pragma region Intial variables
		size_t start = 8;
		#pragma endregion

		#pragma region Basic values
		Mask = std::make_shared<XBITSET<32>>(bin_t(data.begin(), data.begin() + 4), Meaning);
		Flags = std::make_shared<XBITSET<32>>(bin_t(data.begin() + 4, data.begin() + 8), DwordMeaningAceType2Flags);
		#pragma endregion

		#pragma region ObjectType
		if(Flags->get(L"ACE_OBJECT_TYPE_PRESENT"))
		{
			ObjectType = std::make_shared<XGUID>(bin_t{ data.begin() + 8, data.begin() + 24 });
			start += 16;
		}
		#pragma endregion

		#pragma region InheritedObjectType
		if(Flags->get(L"ACE_INHERITED_OBJECT_TYPE_PRESENT"))
		{
			InheritedObjectType = std::make_shared<XGUID>(bin_t{ data.begin() + start, data.begin() + start + 16 });
			start += 16;
		}
		#pragma endregion

		#pragma region Sid
		Sid = std::make_shared<XSID>(bin_t(data.begin() + start, data.end()));
		#pragma endregion

		#pragma region ApplicationData
		bin_t temp;
		std::copy(data.begin() + start + ((bin_t)*Sid).size(), data.end(), std::back_inserter(temp));
		#pragma endregion

		#pragma region Additional structures based on ApplicationData
		if(temp.size())
		{
			ApplicationData = std::make_shared<bin_t>(temp);

			switch(Type)
			{
				case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
				case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
				case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
					ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(*ApplicationData);
					break;
				default:;
			}
		}
		#pragma endregion
	}
	//********************************************************************************************
	XACE_TYPE3::XACE_TYPE3(const msxml_et& xml, const unsigned char type, const dword_meaning_t& meaning) : XACE_TYPE(type, meaning)
	{
		#pragma region Check for a correct input type
		CheckType();
		#pragma endregion

		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XACE_TYPE3: invalid input XML");
		#pragma endregion

		#pragma region Mask
		msxml_et mask = xml->selectSingleNode(L"AccessMask");
		if(nullptr == mask)
			throw std::exception("XACE_TYPE3: cannot find 'AccessMask' XML node");

		Mask = std::make_shared<XBITSET<32>>(mask, Meaning);
		#pragma endregion

		#pragma region Flags
		msxml_et flags = xml->selectSingleNode(L"Flags");
		if(nullptr != flags)
			Flags = std::make_shared<XBITSET<32>>(flags, DwordMeaningAceType2Flags);
		else
			Flags = std::make_shared<XBITSET<32>>(bin_t{ 0x00, 0x00, 0x00, 0x00 }, DwordMeaningAceType2Flags);
		#pragma endregion

		#pragma region ObjectType
		ObjectType = nullptr;

		msxml_et objectType = xml->selectSingleNode(L"ObjectType");
		if(nullptr != objectType)
		{
			ObjectType = std::make_shared<XGUID>(objectType);
			Flags->set(L"ACE_OBJECT_TYPE_PRESENT", true);
		}
		#pragma endregion

		#pragma region InheritedObjectType
		InheritedObjectType = nullptr;

		msxml_et inheritedObjectType = xml->selectSingleNode(L"InheritedObjectType");
		if(nullptr != inheritedObjectType)
		{
			InheritedObjectType = std::make_shared<XGUID>(inheritedObjectType);
			Flags->set(L"ACE_INHERITED_OBJECT_TYPE_PRESENT", true);
		}
		#pragma endregion

		#pragma region Sid
		msxml_et sid = xml->selectSingleNode(L"SID");
		if(nullptr == sid)
			throw std::exception("XACE_TYPE3: cannot find 'SID' XML node");

		Sid = std::make_shared<XSID>(sid);
		#pragma endregion

		#pragma region ApplicationData
		ApplicationData = nullptr;

		msxml_et applicationData = xml->selectSingleNode(L"ApplicationData");
		if(nullptr != applicationData)
			ApplicationData = std::make_shared<bin_t>(from_hex_codes((wchar_t*)applicationData->text));
		#pragma endregion

		#pragma region ConditionalExpression
		msxml_et conditionalExpression = xml->selectSingleNode(L"ConditionalExpression");
		if(nullptr != conditionalExpression)
		{
			switch(Type)
			{
				case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
				case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
				case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
					break;
				default:
					throw std::exception("XACE_TYPE3: usage of 'ConditionalExpression' with incorrect ACE type");
			}

			ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(conditionalExpression);
			ApplicationData = std::make_shared<bin_t>((bin_t)*ConditionalExpression);
		}
		else
		{
			if(nullptr != ApplicationData)
			{
				switch(Type)
				{
					case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
					case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
					case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
						ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(*ApplicationData);
						break;
					default:;
				}
			}
		}
		#pragma endregion
	}
	//********************************************************************************************
	XACE_TYPE3::operator bin_t() const
	{
		#pragma region Additional check
		if((nullptr == Sid) || (nullptr == Mask))
			throw std::exception("XACE_TYPE3: initialize data first");
		#pragma endregion

		#pragma region Initial variables
		bin_t result;

		bin_t applicationData;
		if(nullptr != ApplicationData)
			applicationData = *ApplicationData;
		#pragma endregion

		#pragma region Mask
		auto MaskData = (bin_t)*Mask;
		std::copy(MaskData.begin(), MaskData.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region Flags
		Flags->set(L"ACE_OBJECT_TYPE_PRESENT", nullptr != ObjectType);
		Flags->set(L"ACE_INHERITED_OBJECT_TYPE_PRESENT", nullptr != InheritedObjectType);

		auto FlagsData = (bin_t)*Flags;
		std::copy(FlagsData.begin(), FlagsData.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region ObjectType
		if(nullptr != ObjectType)
		{
			auto bin = (bin_t)*ObjectType;
			std::copy(bin.begin(), bin.end(), std::back_inserter(result));
		}
		#pragma endregion

		#pragma region InheritedObjectType                                                                               
		if(nullptr != InheritedObjectType)
		{
			auto bin = (bin_t)*InheritedObjectType;
			std::copy(bin.begin(), bin.end(), std::back_inserter(result));
		}
		#pragma endregion

		#pragma region Sid
		auto SidData = (bin_t)*Sid;
		std::copy(SidData.begin(), SidData.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region ApplicationData
		if(nullptr != ConditionalExpression)
		{
			switch(Type)
			{
				case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
				case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
				case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
					applicationData = (bin_t)*ConditionalExpression;
					break;
				default:;
			}
		}

		std::copy(applicationData.begin(), applicationData.end(), std::back_inserter(result));
		#pragma endregion

		return result;
	}
	//********************************************************************************************
	XACE_TYPE3::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XACE_TYPE3: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et aceData = xml->createElement(std::wstring(root.value_or(L"AceData")).c_str());
			if(nullptr == aceData)
				throw std::exception("XACE_TYPE3: cannot make root XML");
			#pragma endregion

			#pragma region Mask
			if(nullptr == Mask)
				throw std::exception("XACE_TYPE3: initialize data first");

			aceData->appendChild(((xml_t)*Mask)(xml, L"AccessMask"));
			#pragma endregion

			#pragma region Flags
			if(nullptr == Flags)
				throw std::exception("XACE_TYPE3: initialize data first");

			aceData->appendChild(((xml_t)*Flags)(xml, L"Flags"));
			#pragma endregion

			#pragma region ObjectType
			if(nullptr != ObjectType)
				aceData->appendChild(((xml_t)*ObjectType)(xml, L"ObjectType"));
			#pragma endregion

			#pragma region InheritedObjectType
			if(nullptr != InheritedObjectType)
				aceData->appendChild(((xml_t)*InheritedObjectType)(xml, L"InheritedObjectType"));
			#pragma endregion

			#pragma region Sid
			if(nullptr == Sid)
				throw std::exception("XACE_TYPE3: initialize data first");

			aceData->appendChild(((xml_t)*Sid)(xml, L"SID"));
			#pragma endregion

			#pragma region ApplicationData
			if(nullptr != ApplicationData)
			{
				msxml_et applicationData = xml->createElement(L"ApplicationData");
				if(nullptr == applicationData)
					throw std::exception("XACE_TYPE3: cannot make 'ApplicationData' XML node");

				applicationData->appendChild(xml->createTextNode(hex_codes(*ApplicationData).c_str()));

				aceData->appendChild(applicationData);
			}
			#pragma endregion

			#pragma region ConditionalExpression
			if(nullptr != ConditionalExpression)
			{
				switch(Type)
				{
					case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
					case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
					case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
						aceData->appendChild(((xml_t)*ConditionalExpression)(xml, L"ConditionalExpression"));
						break;
					default:;
				}
			}
			#pragma endregion

			return aceData;
		};
	}
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
	#pragma region Class for XACE_TYPE4
	//********************************************************************************************
	struct XACE_TYPE4 : public XACE_TYPE
	{
		/// <summary>Class for:
		///  <para>ACCESS_ALLOWED_CALLBACK_ACE_TYPE</para>
		///  <para>ACCESS_DENIED_CALLBACK_ACE_TYPE</para>
		///  <para>SYSTEM_AUDIT_CALLBACK_ACE_TYPE</para>
		///  <para>SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE</para>
		/// </summary>

		XACE_TYPE4() = delete;
		~XACE_TYPE4() = default;

		XACE_TYPE4(
			const unsigned char& /*type*/,
			const XSID& /*Sid*/,
			const XBITSET<32>& /*Mask*/ = { (DWORD)0, DwordMeaningDefault },
			const std::optional<XCONDITIONAL_EXPRESSION>& /*ConditionalExpression*/ = std::nullopt,
			const std::optional<XSECURITY_ATTRIBUTE_V1>& /*ResourseClaims*/ = std::nullopt,
			const std::optional<bin_t>& /*ApplicationData*/ = std::nullopt
		);

		XACE_TYPE4(const bin_t&, const unsigned char type, const dword_meaning_t&);
		XACE_TYPE4(const msxml_et&, const unsigned char type, const dword_meaning_t&);

		explicit operator bin_t() const;
		explicit operator xml_t() const;

		std::shared_ptr<XBITSET<32>> Mask;
		std::shared_ptr<XSID> Sid;
		std::shared_ptr<bin_t> ApplicationData;

		std::shared_ptr<XSECURITY_ATTRIBUTE_V1> ResourseClaims; // The property exists only in case of SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE

		std::shared_ptr<XCONDITIONAL_EXPRESSION> ConditionalExpression; // The property exists only in case of ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_ACE and SYSTEM_AUDIT_CALLBACK_ACE

	private:
		void CheckType()
		{
			switch(Type)
			{
				case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
				case ACCESS_DENIED_CALLBACK_ACE_TYPE:
				case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
				case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
					break;
				default:
					throw std::exception("XACE_TYPE4: incorrect ACE type");
			}
		}
	};
	//********************************************************************************************
	XACE_TYPE4::XACE_TYPE4(
		const unsigned char& type,
		const XSID& sid,
		const XBITSET<32>& mask,
		const std::optional<XCONDITIONAL_EXPRESSION>& conditionalExpression,
		const std::optional<XSECURITY_ATTRIBUTE_V1>& resourseClaims,
		const std::optional<bin_t>& applicationData
	) : XACE_TYPE(type, mask.Meaning)
	{
		CheckType();

		Mask = std::make_shared<XBITSET<32>>(mask);
		Sid = std::make_shared<XSID>(sid);

		if(applicationData)
			ApplicationData = std::make_shared<bin_t>(applicationData.value());

		switch(Type)
		{
			case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
			case ACCESS_DENIED_CALLBACK_ACE_TYPE:
			case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
				if(!conditionalExpression && applicationData)
					ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(*ApplicationData);
				else
				{
					if(conditionalExpression)
					{
						ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(conditionalExpression.value());
						ApplicationData = std::make_shared<bin_t>((bin_t)*ConditionalExpression);
					}
				}

				break;
			case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
				if(!resourseClaims && applicationData)
					ResourseClaims = std::make_shared<XSECURITY_ATTRIBUTE_V1>(*ApplicationData);
				else
				{
					if(resourseClaims)
					{
						ResourseClaims = std::make_shared<XSECURITY_ATTRIBUTE_V1>(resourseClaims.value());
						ApplicationData = std::make_shared<bin_t>((bin_t)*ResourseClaims);
					}
				}

				if(ResourseClaims->Values.size() > 1)
					throw std::exception("XACE_TYPE4: only a single value allowed for SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE");

				break;
			default:;
		}
	}
	//********************************************************************************************
	XACE_TYPE4::XACE_TYPE4(const bin_t& data, const unsigned char type, const dword_meaning_t& meaning) : XACE_TYPE(type, meaning)
	{
		#pragma region Check for a correct input type
		CheckType();
		#pragma endregion

		#pragma region Intial variables
		size_t start = 4;
		#pragma endregion

		#pragma region Basic values
		Mask = std::make_shared<XBITSET<32>>(bin_t(data.begin(), data.begin() + 4), Meaning);
		#pragma endregion

		#pragma region Sid
		Sid = std::make_shared<XSID>(bin_t(data.begin() + start, data.end()));
		#pragma endregion

		#pragma region ApplicationData
		ApplicationData = std::make_shared<bin_t>(data.begin() + start + ((bin_t)*Sid).size(), data.end());
		#pragma endregion

		#pragma region Additional structures based on ApplicationData
		switch(Type)
		{
			case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
			case ACCESS_DENIED_CALLBACK_ACE_TYPE:
			case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
				ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(*ApplicationData);
				break;
			case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
				ResourseClaims = std::make_shared<XSECURITY_ATTRIBUTE_V1>(*ApplicationData);
				break;
			default:;
		}
		#pragma endregion
	}
	//********************************************************************************************
	XACE_TYPE4::XACE_TYPE4(const msxml_et& xml, const unsigned char type, const dword_meaning_t& meaning) : XACE_TYPE(type, meaning)
	{
		#pragma region Check for a correct input type
		CheckType();
		#pragma endregion

		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XACE_TYPE4: invalid input XML");
		#pragma endregion

		#pragma region Mask
		msxml_et mask = xml->selectSingleNode(L"AccessMask");
		if(nullptr == mask)
			throw std::exception("XACE_TYPE4: cannot find 'AccessMask' XML node");

		Mask = std::make_shared<XBITSET<32>>(mask, Meaning);
		#pragma endregion

		#pragma region Sid
		msxml_et sid = xml->selectSingleNode(L"SID");
		if(nullptr == sid)
			throw std::exception("XACE_TYPE4: cannot find 'SID' XML node");

		Sid = std::make_shared<XSID>(sid);
		#pragma endregion

		#pragma region ApplicationData
		ApplicationData = nullptr;

		msxml_et applicationData = xml->selectSingleNode(L"ApplicationData");
		if(nullptr != applicationData)
			ApplicationData = std::make_shared<bin_t>(from_hex_codes((wchar_t*)applicationData->text));
		#pragma endregion

		#pragma region ConditionalExpression
		msxml_et conditionalExpression = xml->selectSingleNode(L"ConditionalExpression");
		if(nullptr != conditionalExpression)
		{
			switch(Type)
			{
				case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
				case ACCESS_DENIED_CALLBACK_ACE_TYPE:
				case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
					break;
				default:
					throw std::exception("XACE_TYPE4: usage of 'ConditionalExpression' with incorrect ACE type");
			}

			ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(conditionalExpression);
			ApplicationData = std::make_shared<bin_t>((bin_t)*ConditionalExpression);
		}
		else
		{
			if(nullptr != ApplicationData)
			{
				switch(Type)
				{
					case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
					case ACCESS_DENIED_CALLBACK_ACE_TYPE:
					case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
						ConditionalExpression = std::make_shared<XCONDITIONAL_EXPRESSION>(*ApplicationData);
						break;
					default:;
				}
			}
		}
		#pragma endregion

		#pragma region ResourseClaims
		msxml_et resourseClaims = xml->selectSingleNode(L"ResourseClaims");
		if(nullptr != resourseClaims)
		{
			if(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE != Type)
				throw std::exception("XACE_TYPE4: usage of 'ResourseClaims' with incorrect ACE type");

			ResourseClaims = std::make_unique<XSECURITY_ATTRIBUTE_V1>(resourseClaims);
			ApplicationData = std::make_shared<bin_t>((bin_t)*ResourseClaims);
		}
		else
		{
			if((nullptr != ApplicationData) && (SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE == Type))
				ResourseClaims = std::make_shared<XSECURITY_ATTRIBUTE_V1>(*ApplicationData);
		}
		#pragma endregion
	}
	//********************************************************************************************
	XACE_TYPE4::operator bin_t() const
	{
		#pragma region Additional check
		if((nullptr == Sid) || (nullptr == Mask))
			throw std::exception("XACE_TYPE4: initialize data first");
		#pragma endregion

		#pragma region Initial variables
		bin_t result;
		
		bin_t applicationData;
		if(nullptr != ApplicationData)
			applicationData = *ApplicationData;
		#pragma endregion

		#pragma region Mask
		auto MaskData = (bin_t)*Mask;
		std::copy(MaskData.begin(), MaskData.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region Sid
		auto SidData = (bin_t)*Sid;
		std::copy(SidData.begin(), SidData.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region ApplicationData
		if(nullptr != ConditionalExpression)
		{
			switch(Type)
			{
				case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
				case ACCESS_DENIED_CALLBACK_ACE_TYPE:
				case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
					applicationData = (bin_t)*ConditionalExpression;
					break;
				default:;
			}
		}

		if((nullptr != ResourseClaims) && (SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE == Type))
			applicationData = (bin_t)*ResourseClaims;

		std::copy(applicationData.begin(), applicationData.end(), std::back_inserter(result));
		#pragma endregion

		return result;
	}
	//********************************************************************************************
	XACE_TYPE4::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XACE_TYPE4: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et aceData = xml->createElement(std::wstring(root.value_or(L"AceData")).c_str());
			if(nullptr == aceData)
				throw std::exception("XACE_TYPE4: cannot make root XML");
			#pragma endregion

			#pragma region Mask
			if(nullptr == Mask)
				throw std::exception("XACE_TYPE4: initialize data first");

			aceData->appendChild(((xml_t)*Mask)(xml, L"AccessMask"));
			#pragma endregion

			#pragma region Sid
			if(nullptr == Sid)
				throw std::exception("XACE_TYPE4: initialize data first");

			aceData->appendChild(((xml_t)*Sid)(xml, L"SID"));
			#pragma endregion

			#pragma region ApplicationData
			if(nullptr != ApplicationData)
			{
				msxml_et applicationData = xml->createElement(L"ApplicationData");
				if(nullptr == applicationData)
					throw std::exception("XACE_TYPE4: cannot make 'ApplicationData' XML node");

				applicationData->appendChild(xml->createTextNode(hex_codes(*ApplicationData).c_str()));

				aceData->appendChild(applicationData);
			}
			#pragma endregion

			#pragma region ConditionalExpression
			if(nullptr != ConditionalExpression)
			{
				switch(Type)
				{
					case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
					case ACCESS_DENIED_CALLBACK_ACE_TYPE:
					case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
						aceData->appendChild(((xml_t)*ConditionalExpression)(xml, L"ConditionalExpression"));
						break;
					default:;
				}
			}
			#pragma endregion

			#pragma region ResourseClaims
			if((nullptr != ResourseClaims) && (SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE == Type))
				aceData->appendChild(((xml_t)*ResourseClaims)(xml, L"ResourseClaims"));
			#pragma endregion

			return aceData;
		};
	}
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
	#pragma region Major ACE class
	//********************************************************************************************
	struct XACE
	{
		XACE() = delete;
		~XACE() = default;

		XACE(const std::variant<XACE_TYPE1, XACE_TYPE2, XACE_TYPE3, XACE_TYPE4>&, const XBITSET<8> & = { (unsigned char)0x00, ByteBitsMeaningAceFlags });

		XACE(const unsigned char*, const dword_meaning_t&);
		XACE(const bin_t&, const dword_meaning_t&);
		XACE(const msxml_et&, const dword_meaning_t&);

		explicit operator bin_t();
		explicit operator xml_t();

		WORD AceSize = 0;
		std::shared_ptr<XBITSET<8>> AceFlags;
		std::shared_ptr<XACE_TYPE> AceData;

		dword_meaning_t Meaning;

		size_t Length = 0;
	};
	//********************************************************************************************
	XACE::XACE(const std::variant<XACE_TYPE1, XACE_TYPE2, XACE_TYPE3, XACE_TYPE4>& variant, const XBITSET<8>& flags) : AceFlags(std::make_shared<XBITSET<8>>(flags))
	{
		std::visit([&](auto&& arg) 
		{
			using T = std::decay_t<decltype(arg)>;

			if constexpr(std::is_same_v<T, XACE_TYPE1>)
				AceData = std::make_shared<XACE_TYPE1>(arg);
			else if constexpr(std::is_same_v<T, XACE_TYPE2>)
				AceData = std::make_shared<XACE_TYPE2>(arg);
			else if constexpr(std::is_same_v<T, XACE_TYPE3>)
				AceData = std::make_shared<XACE_TYPE3>(arg);
			else if constexpr(std::is_same_v<T, XACE_TYPE4>)
				AceData = std::make_shared<XACE_TYPE4>(arg);
		}, variant);
	}
	//********************************************************************************************
	XACE::XACE(const unsigned char* data, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region AceType
		unsigned char AceType = data[0];
		#pragma endregion

		#pragma region AceFlags
		AceFlags = std::make_shared<XBITSET<8>>(data + 1, ByteBitsMeaningAceFlags);
		#pragma endregion

		#pragma region AceSize
		((BYTE*)&AceSize)[0] = data[2];
		((BYTE*)&AceSize)[1] = data[3];

		if(0 == AceSize)
			throw std::exception("XACE: invalid AceSize");
		#pragma endregion

		#pragma region AceData
		auto aceData = bin_t{ data + 4, data + AceSize };

		switch(AceType)
		{
			#pragma region ACCESS_ALLOWED_ACE_TYPE
			case ACCESS_ALLOWED_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_ACE_TYPE
			case ACCESS_DENIED_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_ACE_TYPE
			case SYSTEM_AUDIT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_ACE_TYPE
			case SYSTEM_ALARM_ACE_TYPE:
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_COMPOUND_ACE_TYPE
			case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_OBJECT_ACE_TYPE
			case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE2>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_OBJECT_ACE_TYPE
			case ACCESS_DENIED_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE2>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_OBJECT_ACE_TYPE
			case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_OBJECT_ACE_TYPE
			case SYSTEM_ALARM_OBJECT_ACE_TYPE:
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_CALLBACK_ACE_TYPE
			case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_CALLBACK_ACE_TYPE
			case ACCESS_DENIED_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
			case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
			case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_CALLBACK_ACE_TYPE
			case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_CALLBACK_ACE_TYPE
			case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
			case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
			case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_MANDATORY_LABEL_ACE_TYPE
			case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
			case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
			case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region default
			default:
				break;
			#pragma endregion
		}
		#pragma endregion

		Length = 4 + AceSize;
	}
	//********************************************************************************************
	XACE::XACE(const bin_t& data, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region AceType
		unsigned char AceType = data[0];
		#pragma endregion

		#pragma region AceFlags
		AceFlags = std::make_shared<XBITSET<8>>(bin_t{ data[1] }, ByteBitsMeaningAceFlags);
		#pragma endregion

		#pragma region AceSize
		((BYTE*)&AceSize)[0] = data[2];
		((BYTE*)&AceSize)[1] = data[3];

		if(0 == AceSize)
			throw std::exception("ACE: invalid AceSize");
		#pragma endregion

		#pragma region AceData
		auto aceData = bin_t{ data.begin() + 4, data.begin() + AceSize };

		switch(AceType)
		{
			#pragma region ACCESS_ALLOWED_ACE_TYPE
			case ACCESS_ALLOWED_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_ACE_TYPE
			case ACCESS_DENIED_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_ACE_TYPE
			case SYSTEM_AUDIT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_ACE_TYPE
			case SYSTEM_ALARM_ACE_TYPE:
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_COMPOUND_ACE_TYPE
			case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_OBJECT_ACE_TYPE
			case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE2>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_OBJECT_ACE_TYPE
			case ACCESS_DENIED_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE2>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_OBJECT_ACE_TYPE
			case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_OBJECT_ACE_TYPE
			case SYSTEM_ALARM_OBJECT_ACE_TYPE:
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_CALLBACK_ACE_TYPE
			case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_CALLBACK_ACE_TYPE
			case ACCESS_DENIED_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
			case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
			case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_CALLBACK_ACE_TYPE
			case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_CALLBACK_ACE_TYPE
			case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
			case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
			case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_MANDATORY_LABEL_ACE_TYPE
			case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
			case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
			case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region default
			default:
				break;
			#pragma endregion
		}
		#pragma endregion

		Length = 4 + AceSize;
	}
	//********************************************************************************************
	XACE::operator bin_t()
	{
		#pragma region Initial check
		if((nullptr == AceData) || (nullptr == AceFlags))
			throw std::exception("ACE: initialize data first");
		#pragma endregion

		bin_t result;

		result.push_back(AceData->Type);

		auto aceFlags = (bin_t)*AceFlags;
		std::copy(aceFlags.begin(), aceFlags.end(), std::back_inserter(result));

		auto aceData = (bin_t)*AceData;

		#pragma warning(push)
		#pragma warning(disable: 4267)
		AceSize = aceData.size() + 4;
		AceSize += (4 - (AceSize % 4)); // MUST be a multiple of 4 to ensure alignment on a DWORD boundary
		#pragma warning(pop)

		result.push_back(((BYTE*)&AceSize)[0]);
		result.push_back(((BYTE*)&AceSize)[1]);

		std::copy(aceData.begin(), aceData.end(), std::back_inserter(result));

		result.resize(AceSize);

		return result;
	}
	//********************************************************************************************
	XACE::XACE(const msxml_et& xml, const dword_meaning_t& meaning) : Meaning(meaning), AceSize(0)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("ACE: invalid input XML");
		#pragma endregion

		#pragma region AceType
		msxml_et aceType = xml->selectSingleNode(L"AceType");
		if(nullptr == aceType)
			throw std::exception("ACE: cannot find 'AceType' XML node");

		unsigned char AceType = _variant_t(aceType->text);
		#pragma endregion

		#pragma region AceFlags
		msxml_et aceFlags = xml->selectSingleNode(L"AceFlags");
		if(nullptr == aceFlags)
			throw std::exception("ACE: cannot find 'AceFlags' XML node");

		AceFlags = std::make_shared<XBITSET<8>>(aceFlags, ByteBitsMeaningAceFlags);
		#pragma endregion

		#pragma region AceData
		msxml_et aceData = xml->selectSingleNode(L"AceData");
		if(nullptr == aceData)
			throw std::exception("ACE: cannot find 'AceData' XML node");

		switch(AceType)
		{
			#pragma region ACCESS_ALLOWED_ACE_TYPE
			case ACCESS_ALLOWED_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_ACE_TYPE
			case ACCESS_DENIED_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_ACE_TYPE
			case SYSTEM_AUDIT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_ACE_TYPE
			case SYSTEM_ALARM_ACE_TYPE:
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_COMPOUND_ACE_TYPE
			case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_OBJECT_ACE_TYPE
			case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE2>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_OBJECT_ACE_TYPE
			case ACCESS_DENIED_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE2>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_OBJECT_ACE_TYPE
			case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_OBJECT_ACE_TYPE
			case SYSTEM_ALARM_OBJECT_ACE_TYPE:
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_CALLBACK_ACE_TYPE
			case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_CALLBACK_ACE_TYPE
			case ACCESS_DENIED_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
			case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
			case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_CALLBACK_ACE_TYPE
			case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_CALLBACK_ACE_TYPE
			case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
			case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
			case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE3>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_MANDATORY_LABEL_ACE_TYPE
			case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
			case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE4>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
			case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
				AceData = std::make_shared<XACE_TYPE1>(aceData, AceType, Meaning);
				break;
			#pragma endregion
			#pragma region default
			default:
				break;
			#pragma endregion
		}
		#pragma endregion
	}
	//********************************************************************************************
	XACE::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if((nullptr == AceData) || (nullptr == AceFlags))
				throw std::exception("ACE: initialize data first");

			if(nullptr == xml)
				throw std::exception("ACE: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et ace = xml->createElement(std::wstring(root.value_or(L"ACE")).c_str());
			if(nullptr == ace)
				throw std::exception("ACE: cannot create root XML node");
			#pragma endregion

			#pragma region AceType
			msxml_et aceType = xml->createElement(L"AceType");
			if(nullptr == aceType)
				throw std::exception("ACE: cannot create 'AceType' XML node");

			aceType->appendChild(xml->createTextNode(_variant_t(AceData->Type).operator _bstr_t()));

			msxml_at typeName = xml->createAttribute(L"TypeName");
			if(nullptr == typeName)
				throw std::exception("ACE: cannot create 'TypeName' XML node");

			typeName->value = typeNames[AceData->Type].c_str();
			aceType->setAttributeNode(typeName);

			ace->appendChild(aceType);
			#pragma endregion

			#pragma region AceFlags
			ace->appendChild(((xml_t)*AceFlags)(xml, L"AceFlags"));
			#pragma endregion

			#pragma region AceData
			ace->appendChild(((xml_t)*AceData)(xml, L"AceData"));
			#pragma endregion

			return ace;
		};
	}
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
	#pragma region Aux functions for making ACE
	//********************************************************************************************
	XACE XACCESS_ALLOWED_ACE(
		const XSID& sid, 
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault }, 
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE1(ACCESS_ALLOWED_ACE_TYPE, sid, mask), ace_flags);
	}
	//********************************************************************************************
	XACE XACCESS_DENIED_ACE(
		const XSID& sid, 
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault }, 
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE1(ACCESS_DENIED_ACE_TYPE, sid, mask), ace_flags);
	}
	//********************************************************************************************
	XACE XSYSTEM_AUDIT_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const XBITSET<8>& ace_flags = { ByteBitsMeaningAceFlags, { L"SUCCESSFUL_ACCESS_ACE_FLAG", L"FAILED_ACCESS_ACE_FLAG" } }
	)
	{
		return XACE(XACE_TYPE1(SYSTEM_AUDIT_ACE_TYPE, sid, mask), ace_flags);
	}
	//********************************************************************************************
	XACE XSYSTEM_MANDATORY_LABEL_ACE(
		const XSID& sid, 
		const XBITSET<32>& mask = { DwordMeaningMandatoryLabel, { L"SYSTEM_MANDATORY_LABEL_NO_WRITE_UP", L"SYSTEM_MANDATORY_LABEL_NO_READ_UP", L"SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP" } },
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE1(SYSTEM_MANDATORY_LABEL_ACE_TYPE, sid, mask), ace_flags);
	}
	//********************************************************************************************
	XACE XSYSTEM_SCOPED_POLICY_ID_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE1(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, sid, mask), ace_flags);
	}
	//********************************************************************************************
	XACE XACCESS_ALLOWED_OBJECT_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const std::optional<XGUID>& objectType = std::nullopt,
		const std::optional<XGUID>& inheritedObjectType = std::nullopt,
		const XBITSET<32>& flags = { (DWORD)0, DwordMeaningAceType2Flags },
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE2(ACCESS_ALLOWED_OBJECT_ACE_TYPE, sid, mask, objectType, inheritedObjectType, flags), ace_flags);
	}
	//********************************************************************************************
	XACE XACCESS_DENIED_OBJECT_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const std::optional<XGUID>& objectType = std::nullopt,
		const std::optional<XGUID>& inheritedObjectType = std::nullopt,
		const XBITSET<32>& flags = { (DWORD)0, DwordMeaningAceType2Flags },
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE2(ACCESS_DENIED_OBJECT_ACE_TYPE, sid, mask, objectType, inheritedObjectType, flags), ace_flags);
	}
	//********************************************************************************************
	XACE XACCESS_ALLOWED_CALLBACK_OBJECT_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const std::optional<XCONDITIONAL_EXPRESSION>& conditionalExpression = std::nullopt,
		const std::optional<XGUID>& objectType = std::nullopt,
		const std::optional<XGUID>& inheritedObjectType = std::nullopt,
		const std::optional<bin_t>& applicationData = std::nullopt,
		const XBITSET<32>& flags = { (DWORD)0, DwordMeaningAceType2Flags },
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE3(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, sid, mask, conditionalExpression, objectType, inheritedObjectType, applicationData, flags), ace_flags);
	}
	//********************************************************************************************
	XACE XACCESS_DENIED_CALLBACK_OBJECT_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const std::optional<XCONDITIONAL_EXPRESSION>& conditionalExpression = std::nullopt,
		const std::optional<XGUID>& objectType = std::nullopt,
		const std::optional<XGUID>& inheritedObjectType = std::nullopt,
		const std::optional<bin_t>& applicationData = std::nullopt,
		const XBITSET<32>& flags = { (DWORD)0, DwordMeaningAceType2Flags },
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE3(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, sid, mask, conditionalExpression, objectType, inheritedObjectType, applicationData, flags), ace_flags);
	}
	//********************************************************************************************
	XACE XSYSTEM_AUDIT_CALLBACK_OBJECT_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const std::optional<XCONDITIONAL_EXPRESSION>& conditionalExpression = std::nullopt,
		const std::optional<XGUID>& objectType = std::nullopt,
		const std::optional<XGUID>& inheritedObjectType = std::nullopt,
		const std::optional<bin_t>& applicationData = std::nullopt,
		const XBITSET<32>& flags = { (DWORD)0, DwordMeaningAceType2Flags },
		const XBITSET<8>& ace_flags = { ByteBitsMeaningAceFlags, { L"SUCCESSFUL_ACCESS_ACE_FLAG", L"FAILED_ACCESS_ACE_FLAG" } }
	)
	{
		return XACE(XACE_TYPE3(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, sid, mask, conditionalExpression, objectType, inheritedObjectType, applicationData, flags), ace_flags);
	}
	//********************************************************************************************
	XACE XSYSTEM_AUDIT_OBJECT_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const std::optional<XGUID>& objectType = std::nullopt,
		const std::optional<XGUID>& inheritedObjectType = std::nullopt,
		const std::optional<bin_t>& applicationData = std::nullopt,
		const XBITSET<32>& flags = { (DWORD)0, DwordMeaningAceType2Flags },
		const XBITSET<8>& ace_flags = { ByteBitsMeaningAceFlags, { L"SUCCESSFUL_ACCESS_ACE_FLAG", L"FAILED_ACCESS_ACE_FLAG" } }
	)
	{
		return XACE(XACE_TYPE3(SYSTEM_AUDIT_OBJECT_ACE_TYPE, sid, mask, std::nullopt, objectType, inheritedObjectType, applicationData, flags), ace_flags);
	}
	//********************************************************************************************
	XACE XACCESS_ALLOWED_CALLBACK_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const std::optional<XCONDITIONAL_EXPRESSION>& conditionalExpression = std::nullopt,
		const std::optional<bin_t>& applicationData = std::nullopt,
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE4(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, sid, mask, conditionalExpression, std::nullopt,  applicationData), ace_flags);
	}
	//********************************************************************************************
	XACE XACCESS_DENIED_CALLBACK_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const std::optional<XCONDITIONAL_EXPRESSION>& conditionalExpression = std::nullopt,
		const std::optional<bin_t>& applicationData = std::nullopt,
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		return XACE(XACE_TYPE4(ACCESS_DENIED_CALLBACK_ACE_TYPE, sid, mask, conditionalExpression, std::nullopt, applicationData), ace_flags);
	}
	//********************************************************************************************
	XACE XSYSTEM_AUDIT_CALLBACK_ACE(
		const XSID& sid,
		const XBITSET<32>& mask = { (DWORD)0, DwordMeaningDefault },
		const std::optional<XCONDITIONAL_EXPRESSION>& conditionalExpression = std::nullopt,
		const std::optional<bin_t>& applicationData = std::nullopt,
		const XBITSET<8>& ace_flags = { ByteBitsMeaningAceFlags, { L"SUCCESSFUL_ACCESS_ACE_FLAG", L"FAILED_ACCESS_ACE_FLAG" } }
	)
	{
		return XACE(XACE_TYPE4(SYSTEM_AUDIT_CALLBACK_ACE_TYPE, sid, mask, conditionalExpression, std::nullopt, applicationData), ace_flags);
	}
	//********************************************************************************************
	XACE XSYSTEM_RESOURCE_ATTRIBUTE_ACE(
		const std::optional<XSECURITY_ATTRIBUTE_V1>& resourseClaims = std::nullopt,
		const std::optional<bin_t>& applicationData = std::nullopt,
		const XBITSET<8>& ace_flags = { (unsigned char)0x00, ByteBitsMeaningAceFlags }
	)
	{
		if(!resourseClaims && !applicationData)
			throw std::exception("XSYSTEM_RESOURCE_ATTRIBUTE_ACE: must be at least one input value");

		return XACE(XACE_TYPE4(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, XSID::Everyone, 0, std::nullopt, resourseClaims, applicationData), ace_flags);
	}
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
};
//********************************************************************************************
