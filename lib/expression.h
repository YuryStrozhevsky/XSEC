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
	#pragma region Base XCONDITIONAL_OPERATOR class
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR() = default;
		virtual ~XCONDITIONAL_OPERATOR() = default;

		virtual explicit operator bin_t() = 0;
		virtual explicit operator xml_t() = 0;

		virtual unsigned char Code() const = 0;
	};
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region XCONDITIONAL_OPERATOR_INT
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_INT : public XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR_INT() = delete;
		~XCONDITIONAL_OPERATOR_INT() = default;

		XCONDITIONAL_OPERATOR_INT(const int&);
		XCONDITIONAL_OPERATOR_INT(const int8_t&);
		XCONDITIONAL_OPERATOR_INT(const int16_t&);
		//XCONDITIONAL_OPERATOR_INT(const int32_t&); // Consider user could use "XSigned32"
		XCONDITIONAL_OPERATOR_INT(const int64_t&);

		XCONDITIONAL_OPERATOR_INT(const int64_t&, const unsigned char&);

		XCONDITIONAL_OPERATOR_INT(bin_t::const_iterator*, bin_t::const_iterator, const unsigned char&);
		XCONDITIONAL_OPERATOR_INT(const msxml_et&, const unsigned char&);

		explicit operator bin_t();
		explicit operator xml_t();

		int64_t Value = 0;
		int8_t Sign = 0;
		int8_t Base = 0;

		unsigned char Code() const override;

		inline static const std::map<unsigned char, std::wstring> Names = {
			{ (unsigned char)0x01, L"INT8" },
			{ (unsigned char)0x02, L"INT16" },
			{ (unsigned char)0x03, L"INT32" },
			{ (unsigned char)0x04, L"INT64" }
		};
		inline static const std::map<std::wstring, unsigned char> Codes = {
			{ L"INT8",  (unsigned char)0x01 },
			{ L"INT16", (unsigned char)0x02 },
			{ L"INT32", (unsigned char)0x03 },
			{ L"INT64", (unsigned char)0x04 }
		};

		private:
		unsigned char code = 0;

		void CheckCode()
		{
			switch(code)
			{
				case 0x01:
				case 0x02:
				case 0x03:
				case 0x04:
					break;
				default:
					throw std::exception("XCONDITIONAL_OPERATOR_INT: incorrect code");
			}
		}
	};
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT::XCONDITIONAL_OPERATOR_INT(const int& value) : Value(value), code((unsigned char)0x04)
	{
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT::XCONDITIONAL_OPERATOR_INT(const int8_t& value) : Value(value), code((unsigned char)0x01)
	{
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT::XCONDITIONAL_OPERATOR_INT(const int16_t& value) : Value(value), code((unsigned char)0x02)
	{
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT::XCONDITIONAL_OPERATOR_INT(const int64_t& value) : Value(value), code((unsigned char)0x04)
	{
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT::XCONDITIONAL_OPERATOR_INT(const int64_t& value, const unsigned char& _code) : Value(value), code(_code)
	{
		CheckCode();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT::XCONDITIONAL_OPERATOR_INT(bin_t::const_iterator* iter, bin_t::const_iterator end, const unsigned char& _code) : code(_code)
	{
		#pragma region Initial check
		if(*iter == end)
			throw std::exception("XCONDITIONAL_OPERATOR_INT: unexpected end of data");

		CheckCode();
		#pragma endregion

		#pragma region Read main value
		((BYTE*)&Value)[0] = *((*iter)++);

		if(code > 0x01)
			((BYTE*)&Value)[1] = *((*iter)++);
		else
			(*iter)++;

		if(code > 0x02)
		{
			((BYTE*)&Value)[2] = *((*iter)++);
			((BYTE*)&Value)[3] = *((*iter)++);
		}
		else
		{
			(*iter)++;
			(*iter)++;
		}

		if(code == 0x04)
		{
			((BYTE*)&Value)[4] = *((*iter)++);
			((BYTE*)&Value)[5] = *((*iter)++);
			((BYTE*)&Value)[6] = *((*iter)++);
			((BYTE*)&Value)[7] = *((*iter)++);
		}
		else
		{
			(*iter)++;
			(*iter)++;
			(*iter)++;
			(*iter)++;
		}
		#pragma endregion

		#pragma region Read additional values
		((BYTE*)&Sign)[0] = *((*iter)++);
		((BYTE*)&Base)[0] = *((*iter)++);
		#pragma endregion
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT::XCONDITIONAL_OPERATOR_INT(const msxml_et& xml, const unsigned char& _code) : code(_code)
	{
		CheckCode();

		Value = _variant_t(xml->text);

		Sign = (Value > 0) ? 0x01 : ((Value < 0) ? 0x02 : 0x03);
		Base = 0x02;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT::operator bin_t()
	{
		bin_t result(11);

		result[0] = code;
		result[1] = ((BYTE*)&Value)[0];
		result[2] = ((BYTE*)&Value)[1];
		result[3] = ((BYTE*)&Value)[2];
		result[4] = ((BYTE*)&Value)[3];
		result[5] = ((BYTE*)&Value)[4];
		result[6] = ((BYTE*)&Value)[5];
		result[7] = ((BYTE*)&Value)[6];
		result[8] = ((BYTE*)&Value)[7];

		result[9] = (Value > 0) ? 0x01 : ((Value < 0) ? 0x02 : 0x03);
		result[10] = 0x02; // No support for other bases for now

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*>)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_OPERATOR_INT: invalid input XML");
			#pragma endregion

			#pragma region Set correct value for root element name
			auto find = XCONDITIONAL_OPERATOR_INT::Names.find(Code());
			if(XCONDITIONAL_OPERATOR_INT::Names.end() == find)
				throw std::exception("XCONDITIONAL_OPERATOR_INT: invalid code value");

			std::wstring _root = find->second;
			#pragma endregion

			#pragma region Root element
			msxml_et op = xml->createElement(_root.c_str());
			if(nullptr == op)
				throw std::exception("XCONDITIONAL_OPERATOR_INT: cannot create root XML element");
			#pragma endregion

			#pragma region Value
			op->appendChild(xml->createTextNode(_variant_t(Value).operator _bstr_t()));
			#pragma endregion

			return op;
		};
	}
	//****************************************************************************************
	unsigned char XCONDITIONAL_OPERATOR_INT::Code() const
	{
		return code;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region XCONDITIONAL_OPERATOR_UNICODE
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_UNICODE : public XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR_UNICODE() = delete;
		~XCONDITIONAL_OPERATOR_UNICODE() = default;

		XCONDITIONAL_OPERATOR_UNICODE(const wchar_t*);
		XCONDITIONAL_OPERATOR_UNICODE(const std::wstring&);

		XCONDITIONAL_OPERATOR_UNICODE(const std::wstring&, const unsigned char&);

		XCONDITIONAL_OPERATOR_UNICODE(bin_t::const_iterator*, bin_t::const_iterator, const unsigned char&);
		XCONDITIONAL_OPERATOR_UNICODE(const msxml_et&, const unsigned char&);

		explicit operator bin_t();
		explicit operator xml_t();

		std::wstring Value;

		unsigned char Code() const override;

		inline static const std::map<unsigned char, std::wstring> Names = {
			{ (unsigned char)0x10, L"XUnicode" },
			{ (unsigned char)0xF8, L"LOCAL_ATTRIBUTE" },
			{ (unsigned char)0xF9, L"USER_ATTRIBUTE" },
			{ (unsigned char)0xFA, L"RESOURCE_ATTRIBUTE" },
			{ (unsigned char)0xFB, L"DEVICE_ATTRIBUTE" }
		};
		inline static const std::map<std::wstring, unsigned char> Codes = {
			{ L"XUnicode", (unsigned char)0x10 },
			{ L"LOCAL_ATTRIBUTE", (unsigned char)0xF8 },
			{ L"USER_ATTRIBUTE", (unsigned char)0xF9 },
			{ L"RESOURCE_ATTRIBUTE", (unsigned char)0xFA },
			{ L"DEVICE_ATTRIBUTE", (unsigned char)0xFB }
		};

		private:
		unsigned char code;

		void CheckCode()
		{
			switch(code)
			{
				case 0x10:
				case 0xF8:
				case 0xF9:
				case 0xFA:
				case 0xFB:
					break;
				default:
					throw std::exception("XCONDITIONAL_OPERATOR_UNICODE: invalid code");
			}
		}
	};
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE::XCONDITIONAL_OPERATOR_UNICODE(const wchar_t* value) : XCONDITIONAL_OPERATOR_UNICODE(std::wstring(value))
	{
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE::XCONDITIONAL_OPERATOR_UNICODE(const std::wstring& value) : Value(value), code((unsigned char)0x10)
	{
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE::XCONDITIONAL_OPERATOR_UNICODE(const std::wstring& value, const unsigned char& _code) : Value(value), code(_code)
	{
		CheckCode();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE::XCONDITIONAL_OPERATOR_UNICODE(bin_t::const_iterator* iter, bin_t::const_iterator end, const unsigned char& _code) : code(_code)
	{
		CheckCode();

		#pragma region Initial variables
		size_t i = 0;
		size_t j = 0;
		size_t k = 0;

		wchar_t ch = L' ';
		DWORD length = 0;
		#pragma endregion

		#pragma region Read length of the XUnicode string
		do
		{
			if(*iter == end)
				throw std::exception("XCONDITIONAL_OPERATOR_UNICODE: unexpected end of data");

			((BYTE*)&length)[i++] = *((*iter)++);
		} while(i < 4);
		#pragma endregion


		#pragma region Read a value of XUnicode string
		i = 0;
		Value.resize(length >> 1);

		do
		{
			if(*iter == end)
				throw std::exception("XCONDITIONAL_OPERATOR_UNICODE: unexpected end of data");

			((BYTE*)&ch)[j++] = *((*iter)++);

			if(2 == j)
			{
				Value[k++] = ch;
				j = 0;
			}
		} while(++i < length);
		#pragma endregion
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE::XCONDITIONAL_OPERATOR_UNICODE(const msxml_et& xml, const unsigned char& _code) : code(_code)
	{
		CheckCode();

		Value = (wchar_t*)xml->text;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE::operator bin_t()
	{
		bin_t result;

		result.push_back(code);

		#pragma region Put information about string length
		DWORD length = Value.size() << 1; // Size in bytes, not wchars

		for(size_t i = 0; i < 4; i++)
			result.push_back(((BYTE*)&length)[i]);
		#pragma endregion

		#pragma region Put information about Value
		for(auto&& element : Value)
		{
			result.push_back(((BYTE*)&element)[0]);
			result.push_back(((BYTE*)&element)[1]);
		}
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*>)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_OPERATOR_UNICODE: invalid input XML");
			#pragma endregion

			#pragma region Set correct value for root element name
			auto find = XCONDITIONAL_OPERATOR_UNICODE::Names.find(code);
			if(XCONDITIONAL_OPERATOR_UNICODE::Names.end() == find)
				throw std::exception("XCONDITIONAL_OPERATOR_UNICODE: invalid code value");

			std::wstring _root = find->second;
			#pragma endregion

			#pragma region Root element
			msxml_et op = xml->createElement(_root.c_str());
			if(nullptr == op)
				throw std::exception("XCONDITIONAL_OPERATOR_UNICODE: cannot create root XML element");
			#pragma endregion

			#pragma region Value
			op->appendChild(xml->createTextNode(Value.c_str()));
			#pragma endregion

			return op;
		};
	}
	//****************************************************************************************
	unsigned char XCONDITIONAL_OPERATOR_UNICODE::Code() const
	{
		return code;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region XCONDITIONAL_OPERATOR_OCTET
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_OCTET : public XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR_OCTET() = delete;
		~XCONDITIONAL_OPERATOR_OCTET() = default;

		XCONDITIONAL_OPERATOR_OCTET(const bin_t&);

		XCONDITIONAL_OPERATOR_OCTET(bin_t::const_iterator*, bin_t::const_iterator);
		XCONDITIONAL_OPERATOR_OCTET(const msxml_et&);

		explicit operator bin_t();
		explicit operator xml_t();

		bin_t Value;

		unsigned char Code() const override;

		inline static const std::map<unsigned char, std::wstring> Names = {
			{ (unsigned char)0x18, L"OCTET" }
		};
		inline static const std::map<std::wstring, unsigned char> Codes = {
			{ L"OCTET", (unsigned char)0x18 }
		};
	};
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_OCTET::XCONDITIONAL_OPERATOR_OCTET(const bin_t& value) : Value(value)
	{
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_OCTET::XCONDITIONAL_OPERATOR_OCTET(bin_t::const_iterator* iter, bin_t::const_iterator end)
	{
		size_t i = 0;
		DWORD length = 0;

		#pragma region Read length of the Octet string
		do
		{
			if(*iter == end)
				throw std::exception("XCONDITIONAL_OPERATOR_OCTET: unexpected end of data");

			((BYTE*)&length)[i++] = *((*iter)++);
		} while(i < 4);
		#pragma endregion

		#pragma region Read a value of Octet string
		i = 0;
		Value.resize(length);

		do
		{
			if(*iter == end)
				throw std::exception("XCONDITIONAL_OPERATOR_OCTET: unexpected end of data");

			Value[i++] = *((*iter)++);

		} while(i < length);
		#pragma endregion
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_OCTET::XCONDITIONAL_OPERATOR_OCTET(const msxml_et& xml)
	{
		Value = from_hex_codes((wchar_t*)xml->text);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_OCTET::operator bin_t()
	{
		bin_t result;

		result.push_back(0x18);

		#pragma region Put information about string length
		DWORD length = Value.size();

		for(size_t i = 0; i < 4; i++)
			result.push_back(((BYTE*)&length)[i]);
		#pragma endregion

		#pragma region Put information about Value
		std::copy(Value.begin(), Value.end(), std::back_inserter(result));
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_OCTET::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*>)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_OPERATOR_OCTET: invalid input XML");
			#pragma endregion

			#pragma region Set correct value for root element name
			auto find = XCONDITIONAL_OPERATOR_OCTET::Names.find(Code());
			if(XCONDITIONAL_OPERATOR_OCTET::Names.end() == find)
				throw std::exception("XCONDITIONAL_OPERATOR_OCTET: invalid code value");

			std::wstring _root = find->second;
			#pragma endregion

			#pragma region Root element
			msxml_et op = xml->createElement(_root.c_str());
			if(nullptr == op)
				throw std::exception("XCONDITIONAL_OPERATOR_OCTET: cannot create root XML element");
			#pragma endregion

			#pragma region Value
			op->appendChild(xml->createTextNode(hex_codes(Value).c_str()));
			#pragma endregion

			return op;
		};
	}
	//****************************************************************************************
	unsigned char XCONDITIONAL_OPERATOR_OCTET::Code() const
	{
		return 0x18;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region XCONDITIONAL_OPERATOR_SID
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_SID : public XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR_SID() = delete;
		~XCONDITIONAL_OPERATOR_SID() = default;

		XCONDITIONAL_OPERATOR_SID(const XSID&);

		XCONDITIONAL_OPERATOR_SID(bin_t::const_iterator*, bin_t::const_iterator);
		XCONDITIONAL_OPERATOR_SID(const msxml_et&);

		explicit operator bin_t();
		explicit operator xml_t();

		std::shared_ptr<XSID> Value;

		unsigned char Code() const override;

		inline static const std::map<unsigned char, std::wstring> Names = {
			{ (unsigned char)0x51, L"SID" }
		};
		inline static const std::map<std::wstring, unsigned char> Codes = {
			{ L"SID", (unsigned char)0x51 }
		};
	};
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_SID::XCONDITIONAL_OPERATOR_SID(const XSID& sid) : Value(std::make_shared<XSID>(sid))
	{
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_SID::XCONDITIONAL_OPERATOR_SID(bin_t::const_iterator* iter, bin_t::const_iterator end)
	{
		#pragma region Initial variables
		size_t i = 0;
		DWORD length = 0;
		#pragma endregion

		#pragma region Read length of the SID operator
		do
		{
			if(*iter == end)
				throw std::exception("XCONDITIONAL_OPERATOR_SID: unexpected end of data");

			((BYTE*)&length)[i++] = *((*iter)++);
		} while(i < 4);
		#pragma endregion

		#pragma region Read a value of SID operator
		Value = std::make_shared<XSID>(bin_t{ *iter, *iter + length });
		*iter += length;
		#pragma endregion
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_SID::XCONDITIONAL_OPERATOR_SID(const msxml_et& xml)
	{
		Value = std::make_shared<XSID>(xml);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_SID::operator bin_t()
	{
		if(nullptr == Value)
			throw std::exception("XCONDITIONAL_OPERATOR_SID: initialize data first");

		bin_t result;

		result.push_back(0x51);

		auto value = (bin_t)*Value;

		#pragma region Put information about string length
		DWORD length = value.size();

		for(size_t i = 0; i < 4; i++)
			result.push_back(((BYTE*)&length)[i]);
		#pragma endregion

		#pragma region Put information about Value
		std::copy(value.begin(), value.end(), std::back_inserter(result));
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_SID::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*>)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_OPERATOR_SID: invalid input XML");

			if(nullptr == Value)
				throw std::exception("XCONDITIONAL_OPERATOR_SID: initialize data first");
			#pragma endregion

			#pragma region Set correct value for root element name
			auto find = XCONDITIONAL_OPERATOR_SID::Names.find(Code());
			if(XCONDITIONAL_OPERATOR_SID::Names.end() == find)
				throw std::exception("XCONDITIONAL_OPERATOR_SID: invalid code value");

			std::wstring _root = find->second;
			#pragma endregion

			return ((xml_t)*Value)(xml, _root.c_str());
		};
	}
	//****************************************************************************************
	unsigned char XCONDITIONAL_OPERATOR_SID::Code() const
	{
		return 0x51;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Declaration for XCONDITIONAL_EXPRESSION
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_URELATIONAL;
	struct XCONDITIONAL_OPERATOR_BRELATIONAL;
	struct XCONDITIONAL_OPERATOR_ULOGICAL;
	struct XCONDITIONAL_OPERATOR_BLOGICAL;
	//****************************************************************************************
	struct XCONDITIONAL_EXPRESSION
	{
		XCONDITIONAL_EXPRESSION() = delete;
		~XCONDITIONAL_EXPRESSION() = default;

		XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_UNICODE&);
		XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_URELATIONAL&);
		XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_BRELATIONAL&);
		XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_ULOGICAL&);
		XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_BLOGICAL&);

		XCONDITIONAL_EXPRESSION(const bin_t&);
		XCONDITIONAL_EXPRESSION(const msxml_et&);

		explicit operator bin_t();
		explicit operator xml_t();

		static std::vector<std::shared_ptr<XCONDITIONAL_OPERATOR>> ReadOperators(bin_t::const_iterator*, bin_t::const_iterator, bool = false);
		static std::shared_ptr<XCONDITIONAL_OPERATOR> ReadOperator(msxml_et, bool = false);

		std::shared_ptr<XCONDITIONAL_OPERATOR> Operator;
	};
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region XCONDITIONAL_OPERATOR_COMPOSITE
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_COMPOSITE : public XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR_COMPOSITE() = delete;
		~XCONDITIONAL_OPERATOR_COMPOSITE() = default;

		using value_type = std::variant<XCONDITIONAL_OPERATOR_INT, XCONDITIONAL_OPERATOR_UNICODE, XCONDITIONAL_OPERATOR_OCTET, XCONDITIONAL_OPERATOR_SID, XCONDITIONAL_OPERATOR_COMPOSITE>;
		using type = std::vector<value_type>;

		XCONDITIONAL_OPERATOR_COMPOSITE(const type&);

		XCONDITIONAL_OPERATOR_COMPOSITE(bin_t::const_iterator*, bin_t::const_iterator);
		XCONDITIONAL_OPERATOR_COMPOSITE(const msxml_et&);

		explicit operator bin_t();
		explicit operator xml_t();

		std::vector<std::shared_ptr<XCONDITIONAL_OPERATOR>> Value;

		unsigned char Code() const override;

		inline static const std::map<unsigned char, std::wstring> Names = {
			{ (unsigned char)0x50, L"COMPOSITE" }
		};
		inline static const std::map<std::wstring, unsigned char> Codes = {
			{ L"COMPOSITE", (unsigned char)0x50 }
		};
	};
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_COMPOSITE::XCONDITIONAL_OPERATOR_COMPOSITE(const type& value)
	{
		for(auto&& element : value)
		{
			std::visit([&](auto&& arg)
			{
				using T = std::decay_t<decltype(arg)>;

				if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_INT>)
					Value.push_back(std::make_shared<XCONDITIONAL_OPERATOR_INT>(arg));
				else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_UNICODE>)
					Value.push_back(std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(arg));
				else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_OCTET>)
					Value.push_back(std::make_shared<XCONDITIONAL_OPERATOR_OCTET>(arg));
				else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_SID>)
					Value.push_back(std::make_shared<XCONDITIONAL_OPERATOR_SID>(arg));
				else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_COMPOSITE>) // ??? TODO: Check we really can do it
					Value.push_back(std::make_shared<XCONDITIONAL_OPERATOR_COMPOSITE>(arg));
				}, element);
		}
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_COMPOSITE::XCONDITIONAL_OPERATOR_COMPOSITE(bin_t::const_iterator* iter, bin_t::const_iterator end)
	{
		#pragma region Initial variables
		size_t i = 0;
		DWORD length = 0;
		#pragma endregion

		#pragma region Read length of the XComposite operator
		do
		{
			if(*iter == end)
				throw std::exception("XCONDITIONAL_OPERATOR_COMPOSITE: unexpected end of data");

			((BYTE*)&length)[i++] = *((*iter)++);
		} while(i < 4);
		#pragma endregion

		#pragma region Read a values of XComposite operator
		// After the operation values would be in reverse order, but it does not matter for the type
		Value = XCONDITIONAL_EXPRESSION::ReadOperators(iter, *iter + length, true);
		#pragma endregion
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_COMPOSITE::XCONDITIONAL_OPERATOR_COMPOSITE(const msxml_et& xml)
	{
		msxml_nt list = xml->selectNodes(L"./node()");

		if(list->length == 0)
			throw std::exception("XCONDITIONAL_OPERATOR_COMPOSITE: invalid XML data");

		for(long i = 0; i < list->length; i++)
			Value.push_back(XCONDITIONAL_EXPRESSION::ReadOperator(list->item[i], true));
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_COMPOSITE::operator bin_t()
	{
		#pragma region Initial variables
		bin_t result;
		bin_t value;
		#pragma endregion

		#pragma region Get binary representations for all values
		for(auto&& element : Value)
		{
			auto element_bin = (bin_t)*element;
			std::copy(element_bin.begin(), element_bin.end(), std::back_inserter(value));
		}
		#pragma endregion

		#pragma region Put header code
		result.push_back(0x50);
		#pragma endregion

		#pragma region Put information about string length
		DWORD length = value.size();

		for(size_t i = 0; i < 4; i++)
			result.push_back(((BYTE*)&length)[i]);
		#pragma endregion

		#pragma region Put information about Value
		std::copy(value.begin(), value.end(), std::back_inserter(result));
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_COMPOSITE::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*>)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_OPERATOR_COMPOSITE: invalid input XML");
			#pragma endregion

			#pragma region Set correct value for root element name
			auto find = XCONDITIONAL_OPERATOR_COMPOSITE::Names.find(Code());
			if(XCONDITIONAL_OPERATOR_COMPOSITE::Names.end() == find)
				throw std::exception("XCONDITIONAL_OPERATOR_COMPOSITE: invalid code value");

			std::wstring _root = find->second;
			#pragma endregion

			#pragma region Root element
			msxml_et op = xml->createElement(_root.c_str());
			if(nullptr == op)
				throw std::exception("XCONDITIONAL_OPERATOR_COMPOSITE: cannot create root XML element");
			#pragma endregion

			#pragma region Value
			for(auto&& element : Value)
				op->appendChild(((xml_t)*element)(xml, std::nullopt));
			#pragma endregion

			return op;
		};
	}
	//****************************************************************************************
	unsigned char XCONDITIONAL_OPERATOR_COMPOSITE::Code() const
	{
		return 0x50;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	using data_operators = std::variant<
		XCONDITIONAL_OPERATOR_INT,
		XCONDITIONAL_OPERATOR_UNICODE,
		XCONDITIONAL_OPERATOR_OCTET,
		XCONDITIONAL_OPERATOR_SID,
		XCONDITIONAL_OPERATOR_COMPOSITE
	>;
	//****************************************************************************************
	#pragma region XCONDITIONAL_OPERATOR_URELATIONAL
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_URELATIONAL : public XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR_URELATIONAL() = delete;
		~XCONDITIONAL_OPERATOR_URELATIONAL() = default;

		using type = std::variant<XCONDITIONAL_OPERATOR_SID, XCONDITIONAL_OPERATOR_COMPOSITE>;

		XCONDITIONAL_OPERATOR_URELATIONAL(const type&, const unsigned char&);

		XCONDITIONAL_OPERATOR_URELATIONAL(const std::shared_ptr<XCONDITIONAL_OPERATOR>&, const unsigned char&);
		XCONDITIONAL_OPERATOR_URELATIONAL(const msxml_et&, const unsigned char&);

		explicit operator bin_t();
		explicit operator xml_t();

		std::shared_ptr<XCONDITIONAL_OPERATOR> Value;

		unsigned char Code() const override;

		inline static const std::map<unsigned char, std::wstring> Names = {
			{ (unsigned char)0x89, L"MEMBER_OF" },
			{ (unsigned char)0x8A, L"DEVICE_MEMBER_OF" },
			{ (unsigned char)0x8B, L"MEMBER_OF_ANY" },
			{ (unsigned char)0x8C, L"DEVICE_MEMBER_OF_ANY" },
			{ (unsigned char)0x90, L"NOT_MEMBER_OF" },
			{ (unsigned char)0x91, L"NOT_DEVICE_MEMBER_OF" },
			{ (unsigned char)0x92, L"NOT_MEMBER_OF_ANY" },
			{ (unsigned char)0x93, L"NOT_DEVICE_MEMBER_OF_ANY" }
		};
		inline static const std::map<std::wstring, unsigned char> Codes = {
			{ L"MEMBER_OF", (unsigned char)0x89 },
			{ L"DEVICE_MEMBER_OF", (unsigned char)0x8A },
			{ L"MEMBER_OF_ANY", (unsigned char)0x8B },
			{ L"DEVICE_MEMBER_OF_ANY", (unsigned char)0x8C },
			{ L"NOT_MEMBER_OF", (unsigned char)0x90 },
			{ L"NOT_DEVICE_MEMBER_OF", (unsigned char)0x91 },
			{ L"NOT_MEMBER_OF_ANY", (unsigned char)0x92 },
			{ L"NOT_DEVICE_MEMBER_OF_ANY", (unsigned char)0x93 }
		};

		private:
		unsigned char code;

		void CheckValue()
		{
			switch(Value->Code())
			{
				case 0x50: // XComposite type
					for(auto&& element : dynamic_cast<XCONDITIONAL_OPERATOR_COMPOSITE*>(Value.get())->Value)
					{
						if(0x51 != element->Code())
							throw std::exception("XCONDITIONAL_OPERATOR_URELATIONAL: invalid data type on stack");
					}

					break;
				case 0x51: // SID type
					break;
				default:
					throw std::exception("XCONDITIONAL_OPERATOR_URELATIONAL: invalid data type on stack");
			}
		}
	};
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL::XCONDITIONAL_OPERATOR_URELATIONAL(const type& value, const unsigned char& _code) : code(_code)
	{
		std::visit([&](auto&& arg)
		{
			using T = std::decay_t<decltype(arg)>;

			if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_SID>)
				Value = std::make_shared<XCONDITIONAL_OPERATOR_SID>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_COMPOSITE>)
			{
				for(auto&& element : arg.Value)
				{
					if(0x51 != element->Code()) // Only "COMPOSITE{SID}" allowed
						throw std::exception("XCONDITIONAL_OPERATOR_URELATIONAL: invalid data type on stack");
				}

				Value = std::make_shared<XCONDITIONAL_OPERATOR_COMPOSITE>(arg);
			}
		}, value);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL::XCONDITIONAL_OPERATOR_URELATIONAL(const std::shared_ptr<XCONDITIONAL_OPERATOR>& value, const unsigned char& _code) : Value(value), code(_code)
	{
		CheckValue();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL::XCONDITIONAL_OPERATOR_URELATIONAL(const msxml_et& xml, const unsigned char& _code) : code(_code)
	{
		msxml_nt list = xml->selectNodes(L"./node()");

		if(list->length != 1)
			throw std::exception("XCONDITIONAL_OPERATOR_URELATIONAL: only a single element allowed in XML");

		Value = XCONDITIONAL_EXPRESSION::ReadOperator(list->item[0]);

		CheckValue();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL::operator bin_t()
	{
		#pragma region Initial check
		if(nullptr == Value)
			throw std::exception("XCONDITIONAL_OPERATOR_URELATIONAL: initialize data first");
		#pragma endregion

		#pragma region Initialize binary data from value first
		bin_t result = (bin_t)*Value;
		#pragma endregion

		#pragma region Put a header for operator after the data
		result.push_back(code);
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*>)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_OPERATOR_URELATIONAL: invalid input XML");

			if(nullptr == Value)
				throw std::exception("XCONDITIONAL_OPERATOR_URELATIONAL: initialize data first");
			#pragma endregion

			#pragma region Set correct value for root element name
			auto find = XCONDITIONAL_OPERATOR_URELATIONAL::Names.find(Code());
			if(XCONDITIONAL_OPERATOR_URELATIONAL::Names.end() == find)
				throw std::exception("XCONDITIONAL_OPERATOR_URELATIONAL: invalid code value");

			std::wstring _root = find->second;
			#pragma endregion

			#pragma region Root element
			msxml_et op = xml->createElement(_root.c_str());
			if(nullptr == op)
				throw std::exception("XCONDITIONAL_OPERATOR_URELATIONAL: cannot create root XML element");
			#pragma endregion

			#pragma region Value
			op->appendChild(((xml_t)*Value)(xml, std::nullopt));
			#pragma endregion

			return op;
		};
	}
	//****************************************************************************************
	unsigned char XCONDITIONAL_OPERATOR_URELATIONAL::Code() const
	{
		return code;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region XCONDITIONAL_OPERATOR_BRELATIONAL
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_BRELATIONAL : public XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR_BRELATIONAL() = delete;
		~XCONDITIONAL_OPERATOR_BRELATIONAL() = default;

		using type1 = std::variant<XCONDITIONAL_OPERATOR_SID, XCONDITIONAL_OPERATOR_INT, XCONDITIONAL_OPERATOR_UNICODE, XCONDITIONAL_OPERATOR_OCTET>;
		using type2 = std::variant<XCONDITIONAL_OPERATOR_SID, XCONDITIONAL_OPERATOR_INT, XCONDITIONAL_OPERATOR_UNICODE, XCONDITIONAL_OPERATOR_OCTET, XCONDITIONAL_OPERATOR_COMPOSITE>;

		XCONDITIONAL_OPERATOR_BRELATIONAL(const XCONDITIONAL_OPERATOR_UNICODE&, const type1&, const unsigned char&);
		XCONDITIONAL_OPERATOR_BRELATIONAL(const XCONDITIONAL_OPERATOR_UNICODE&, const type2&, const unsigned char&);

		XCONDITIONAL_OPERATOR_BRELATIONAL(const std::shared_ptr<XCONDITIONAL_OPERATOR>&, const std::shared_ptr<XCONDITIONAL_OPERATOR>&, const unsigned char&);
		XCONDITIONAL_OPERATOR_BRELATIONAL(const msxml_et&, const unsigned char&);

		explicit operator bin_t();
		explicit operator xml_t();

		std::shared_ptr<XCONDITIONAL_OPERATOR> LHS;
		std::shared_ptr<XCONDITIONAL_OPERATOR> RHS;

		unsigned char Code() const override;

		inline static const std::map<unsigned char, std::wstring> Names = {
			{ (unsigned char)0x80, L"EQUAL" },
			{ (unsigned char)0x81, L"NOT_EQUAL" },
			{ (unsigned char)0x82, L"LESS" },
			{ (unsigned char)0x83, L"LESS_OR_EQUAL" },
			{ (unsigned char)0x84, L"MORE" },
			{ (unsigned char)0x85, L"MORE_OR_EQUAL" },
			{ (unsigned char)0x86, L"CONTAINS" },
			{ (unsigned char)0x88, L"ANY_OF" },
			{ (unsigned char)0x8E, L"NOT_CONTAINS" },
			{ (unsigned char)0x8F, L"NOT_ANY_OF" }
		};
		inline static const std::map<std::wstring, unsigned char> Codes = {
			{ L"EQUAL", (unsigned char)0x80 },
			{ L"NOT_EQUAL", (unsigned char)0x81 },
			{ L"LESS", (unsigned char)0x82 },
			{ L"LESS_OR_EQUAL", (unsigned char)0x83 },
			{ L"MORE", (unsigned char)0x84 },
			{ L"MORE_OR_EQUAL", (unsigned char)0x85 },
			{ L"CONTAINS", (unsigned char)0x86 },
			{ L"ANY_OF", (unsigned char)0x88 },
			{ L"NOT_CONTAINS", (unsigned char)0x8E },
			{ L"NOT_ANY_OF", (unsigned char)0x8F }
		};

	private:
		unsigned char code;

		void CheckValues()
		{
			switch(LHS->Code())
			{
				case 0xF8: // XLocal Attribute
				case 0xF9: // XUser Attribute
				case 0xFA: // XResource Attribute
				case 0xFB: // XDevice Attribute
					break;
				default:
					throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: invalid type on stack - LHS must be an attribute");
			}

			switch(RHS->Code())
			{
				case 0x01: // Signed Int8 Type
				case 0x02: // Signed Int16 Type
				case 0x03: // Signed Int32 Type
				case 0x04: // Signed Int64 Type
				case 0x18: // Octet Type
				case 0x51: // SID
					break;
				case 0x50: // XComposite Type
					switch(code)
					{
						case 0x80: // ==
						case 0x81: // !=
						case 0x86: // XContains
						case 0x88: // XAny_of
						case 0x8E: // XNot_Contains
						case 0x8F: // XNot_Any_of
							break;
						default:
							throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: invalid type on stack - RHS must NOT be a XComposite Type");
					}
					break;
				case 0x10: // XUnicode Type
				case 0xF8: // XLocal Attribute
				case 0xF9: // XUser Attribute
				case 0xFA: // XResource Attribute
				case 0xFB: // XDevice Attribute
					break;
				default:
					throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: invalid type on stack - RHS must be a data type");
			}
		}
	};
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL::XCONDITIONAL_OPERATOR_BRELATIONAL(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const type1& rhs, const unsigned char& _code) : code(_code)
	{
		switch(code)
		{
			case 0x82: // <
			case 0x83: // <=
			case 0x84: // >
			case 0x85: // >=
				break;
			default:
				throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: incorrect constructor usage");
		}

		LHS = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(lhs);

		std::visit([&](auto&& arg)
		{
			using T = std::decay_t<decltype(arg)>;

			if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_INT>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_INT>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_UNICODE>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_OCTET>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_OCTET>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_SID>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_SID>(arg);
			}, rhs);

		CheckValues();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL::XCONDITIONAL_OPERATOR_BRELATIONAL(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const type2& rhs, const unsigned char& _code) : code(_code)
	{
		switch(code)
		{
			case 0x80: // ==
			case 0x81: // !=
			case 0x86: // XContains
			case 0x88: // XAny_of
			case 0x8E: // XNot_Contains
			case 0x8F: // XNot_Any_of
				break;
			default:
				throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: incorrect constructor usage");
		}

		LHS = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(lhs);

		std::visit([&](auto&& arg)
		{
			using T = std::decay_t<decltype(arg)>;

			if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_INT>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_INT>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_UNICODE>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_OCTET>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_OCTET>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_SID>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_SID>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_COMPOSITE>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_COMPOSITE>(arg);
		}, rhs);

		CheckValues();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL::XCONDITIONAL_OPERATOR_BRELATIONAL(
		const std::shared_ptr<XCONDITIONAL_OPERATOR>& lhs, 
		const std::shared_ptr<XCONDITIONAL_OPERATOR>& rhs, 
		const unsigned char& _code
	) : LHS(lhs), RHS(rhs), code(_code)
	{
		CheckValues();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL::XCONDITIONAL_OPERATOR_BRELATIONAL(const msxml_et& xml, const unsigned char& _code) : code(_code)
	{
		#pragma region LHS
		msxml_et lhs = xml->selectSingleNode(L"LHS");
		if(nullptr == lhs)
			throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: cannot find 'LHS' XML node");

		msxml_nt lhs_list = lhs->selectNodes(L"./node()");

		if(lhs_list->length != 1)
			throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: only a single element allowed in LHS XML");

		LHS = XCONDITIONAL_EXPRESSION::ReadOperator(lhs_list->item[0]);
		#pragma endregion

		#pragma region RHS
		msxml_et rhs = xml->selectSingleNode(L"RHS");
		if(nullptr == rhs)
			throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: cannot find 'RHS' XML node");

		msxml_nt rhs_list = rhs->selectNodes(L"./node()");

		if(rhs_list->length != 1)
			throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: only a single element allowed in RHS XML");

		RHS = XCONDITIONAL_EXPRESSION::ReadOperator(rhs_list->item[0]);
		#pragma endregion

		CheckValues();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL::operator bin_t()
	{
		#pragma region Initial check
		if((nullptr == LHS) || (nullptr == RHS))
			throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: initialize data first");
		#pragma endregion

		#pragma region Initialize binary data from value first
		bin_t result = (bin_t)*LHS;

		bin_t rhs_bin = (bin_t)*RHS;
		std::copy(rhs_bin.begin(), rhs_bin.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region Put a header for operator after the data
		result.push_back(code);
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*>)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: invalid input XML");

			if((nullptr == LHS) || (nullptr == RHS))
				throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: initialize data first");
			#pragma endregion

			#pragma region Set correct value for root element name
			auto find = XCONDITIONAL_OPERATOR_BRELATIONAL::Names.find(Code());
			if(XCONDITIONAL_OPERATOR_BRELATIONAL::Names.end() == find)
				throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: invalid code value");

			std::wstring _root = find->second;
			#pragma endregion

			#pragma region Root element
			msxml_et op = xml->createElement(_root.c_str());
			if(nullptr == op)
				throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: cannot create root XML element");
			#pragma endregion

			#pragma region LHS
			msxml_et lhs = xml->createElement(L"LHS");
			if(nullptr == lhs)
				throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: cannot create 'LHS' XML element");

			lhs->appendChild(((xml_t)*LHS)(xml, std::nullopt));
			op->appendChild(lhs);
			#pragma endregion

			#pragma region RHS
			msxml_et rhs = xml->createElement(L"RHS");
			if(nullptr == rhs)
				throw std::exception("XCONDITIONAL_OPERATOR_BRELATIONAL: cannot create 'RHS' XML element");

			rhs->appendChild(((xml_t)*RHS)(xml, std::nullopt));
			op->appendChild(rhs);
			#pragma endregion

			return op;
		};
	}
	//****************************************************************************************
	unsigned char XCONDITIONAL_OPERATOR_BRELATIONAL::Code() const
	{
		return code;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region XCONDITIONAL_OPERATOR_ULOGICAL
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_ULOGICAL : public XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR_ULOGICAL() = delete;
		~XCONDITIONAL_OPERATOR_ULOGICAL() = default;

		XCONDITIONAL_OPERATOR_ULOGICAL(const XCONDITIONAL_OPERATOR_UNICODE&, const unsigned char&);

		XCONDITIONAL_OPERATOR_ULOGICAL(const std::shared_ptr<XCONDITIONAL_OPERATOR>&, const unsigned char&);
		XCONDITIONAL_OPERATOR_ULOGICAL(const msxml_et&, const unsigned char&);

		explicit operator bin_t();
		explicit operator xml_t();

		std::shared_ptr<XCONDITIONAL_OPERATOR> Value;

		unsigned char Code() const override;

		inline static const std::map<unsigned char, std::wstring> Names = {
			{ (unsigned char)0x87, L"EXISTS" },
			{ (unsigned char)0x8D, L"NOT_EXISTS" },
			{ (unsigned char)0xA2, L"LOGICAL_NOT" }
		};
		inline static const std::map<std::wstring, unsigned char> Codes = {
			{ L"EXISTS", (unsigned char)0x87 },
			{ L"NOT_EXISTS", (unsigned char)0x8D },
			{ L"LOGICAL_NOT", (unsigned char)0xA2 }
		};

		private:
		unsigned char code;

		void CheckValue()
		{
			switch(code)
			{
				case 0x87: // XExists
				case 0x8D: // XNot_Exists
					switch(Value->Code())
					{
						case 0xF8: // XLocal Attribute
						case 0xFA: // XResource Attribute
							break;
						default:
							throw std::exception("XCONDITIONAL_OPERATOR_ULOGICAL: only 'Local' and 'Resource' Attribute Type allowed for 'Exists' and 'Not_Exists'");
					}
					break;
				default:; // Anything allowed for "Logical Not"(!) operator
			}
		}
	};
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_ULOGICAL::XCONDITIONAL_OPERATOR_ULOGICAL(const XCONDITIONAL_OPERATOR_UNICODE& value, const unsigned char& _code) : Value(std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(value)), code(_code)
	{
		CheckValue();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_ULOGICAL::XCONDITIONAL_OPERATOR_ULOGICAL(const std::shared_ptr<XCONDITIONAL_OPERATOR>& value, const unsigned char& _code) : Value(value), code(_code)
	{
		CheckValue();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_ULOGICAL::XCONDITIONAL_OPERATOR_ULOGICAL(const msxml_et& xml, const unsigned char& _code) : code(_code)
	{
		msxml_nt list = xml->selectNodes(L"./node()");

		if(list->length != 1)
			throw std::exception("XCONDITIONAL_EXPRESSION: only a single element allowed in XML");

		Value = XCONDITIONAL_EXPRESSION::ReadOperator(list->item[0]);

		CheckValue();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_ULOGICAL::operator bin_t()
	{
		#pragma region Initial check
		if(nullptr == Value)
			throw std::exception("XCONDITIONAL_OPERATOR_ULOGICAL: initialize data first");
		#pragma endregion

		#pragma region Initialize binary data from value first
		bin_t result = (bin_t)*Value;
		#pragma endregion

		#pragma region Put a header for operator after the data
		result.push_back(code);
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_ULOGICAL::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*>)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_OPERATOR_ULOGICAL: invalid input XML");
			#pragma endregion

			#pragma region Set correct value for root element name
			auto find = XCONDITIONAL_OPERATOR_ULOGICAL::Names.find(Code());
			if(XCONDITIONAL_OPERATOR_ULOGICAL::Names.end() == find)
				throw std::exception("XCONDITIONAL_OPERATOR_ULOGICAL: invalid code value");

			std::wstring _root = find->second;
			#pragma endregion

			#pragma region Root element
			msxml_et op = xml->createElement(_root.c_str());
			if(nullptr == op)
				throw std::exception("XCONDITIONAL_OPERATOR_ULOGICAL: cannot create root XML element");
			#pragma endregion

			#pragma region Value
			op->appendChild(((xml_t)*Value)(xml, std::nullopt));
			#pragma endregion

			return op;
		};
	}
	//****************************************************************************************
	unsigned char XCONDITIONAL_OPERATOR_ULOGICAL::Code() const
	{
		return code;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region XCONDITIONAL_OPERATOR_BLOGICAL
	//****************************************************************************************
	struct XCONDITIONAL_OPERATOR_BLOGICAL : public XCONDITIONAL_OPERATOR
	{
		XCONDITIONAL_OPERATOR_BLOGICAL() = delete;
		~XCONDITIONAL_OPERATOR_BLOGICAL() = default;

		XCONDITIONAL_OPERATOR_BLOGICAL(const std::shared_ptr<XCONDITIONAL_OPERATOR>&, const std::shared_ptr<XCONDITIONAL_OPERATOR>&, const unsigned char&);
		XCONDITIONAL_OPERATOR_BLOGICAL(const msxml_et&, const unsigned char&);

		explicit operator bin_t();
		explicit operator xml_t();

		std::shared_ptr<XCONDITIONAL_OPERATOR> LHS;
		std::shared_ptr<XCONDITIONAL_OPERATOR> RHS;

		unsigned char Code() const override;

		inline static const std::map<unsigned char, std::wstring> Names = {
			{ (unsigned char)0xA0, L"LOGICAL_AND" },
			{ (unsigned char)0xA1, L"LOGICAL_OR" }
		};
		inline static const std::map<std::wstring, unsigned char> Codes = {
			{ L"LOGICAL_AND", (unsigned char)0xA0 },
			{ L"LOGICAL_OR", (unsigned char)0xA1 }
		};

		private:
		unsigned char code;

		void CheckCode()
		{
			switch(code)
			{
				case 0xA0:
				case 0xA1:
					break;
				default:
					throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: invalid code");
			}
		}
	};
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BLOGICAL::XCONDITIONAL_OPERATOR_BLOGICAL(
		const std::shared_ptr<XCONDITIONAL_OPERATOR>& lhs, 
		const std::shared_ptr<XCONDITIONAL_OPERATOR>& rhs, 
		const unsigned char& _code
	) : LHS(lhs), RHS(rhs), code(_code)
	{
		// Anything allowed for "Binary Logical Operators"
		CheckCode();
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BLOGICAL::XCONDITIONAL_OPERATOR_BLOGICAL(const msxml_et& xml, const unsigned char& _code) : code(_code)
	{
		CheckCode();

		#pragma region LHS
		msxml_et lhs = xml->selectSingleNode(L"LHS");
		if(nullptr == lhs)
			throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: cannot find 'LHS' XML node");

		msxml_nt lhs_list = lhs->selectNodes(L"./node()");

		if(lhs_list->length != 1)
			throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: only a single element allowed in LHS XML");

		LHS = XCONDITIONAL_EXPRESSION::ReadOperator(lhs_list->item[0]);
		#pragma endregion

		#pragma region RHS
		msxml_et rhs = xml->selectSingleNode(L"RHS");
		if(nullptr == rhs)
			throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: cannot find 'RHS' XML node");

		msxml_nt rhs_list = rhs->selectNodes(L"./node()");

		if(rhs_list->length != 1)
			throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: only a single element allowed in RHS XML");

		RHS = XCONDITIONAL_EXPRESSION::ReadOperator(rhs_list->item[0]);
		#pragma endregion
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BLOGICAL::operator bin_t()
	{
		#pragma region Initial check
		if((nullptr == LHS) || (nullptr == RHS))
			throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: initialize data first");
		#pragma endregion

		#pragma region Initialize binary data from value first
		bin_t result = (bin_t)*LHS;

		bin_t rhs_bin = (bin_t)*RHS;
		std::copy(rhs_bin.begin(), rhs_bin.end(), std::back_inserter(result));
		#pragma endregion

		#pragma region Put a header for operator after the data
		result.push_back(code);
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BLOGICAL::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*>)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: invalid input XML");

			if((nullptr == LHS) || (nullptr == RHS))
				throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: initialize data first");
			#pragma endregion

			#pragma region Set correct value for root element name
			auto find = XCONDITIONAL_OPERATOR_BLOGICAL::Names.find(Code());
			if(XCONDITIONAL_OPERATOR_BLOGICAL::Names.end() == find)
				throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: invalid code value");

			std::wstring _root = find->second;
			#pragma endregion

			#pragma region Root element
			msxml_et op = xml->createElement(_root.c_str());
			if(nullptr == op)
				throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: cannot create root XML element");
			#pragma endregion

			#pragma region LHS
			msxml_et lhs = xml->createElement(L"LHS");
			if(nullptr == lhs)
				throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: cannot create 'LHS' XML element");

			lhs->appendChild(((xml_t)*LHS)(xml, std::nullopt));
			op->appendChild(lhs);
			#pragma endregion

			#pragma region RHS
			msxml_et rhs = xml->createElement(L"RHS");
			if(nullptr == rhs)
				throw std::exception("XCONDITIONAL_OPERATOR_BLOGICAL: cannot create 'RHS' XML element");

			rhs->appendChild(((xml_t)*RHS)(xml, std::nullopt));
			op->appendChild(rhs);
			#pragma endregion

			return op;
		};
	}
	//****************************************************************************************
	unsigned char XCONDITIONAL_OPERATOR_BLOGICAL::Code() const
	{
		return code;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Realization for XCONDITIONAL_EXPRESSION
	//****************************************************************************************
	XCONDITIONAL_EXPRESSION::XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_UNICODE& value)
	{
		if(0x10 == value.Code())
			throw std::exception("XCONDITIONAL_EXPRESSION: only attributes allowed here");

		Operator = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(value);
	}
	//****************************************************************************************
	XCONDITIONAL_EXPRESSION::XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_URELATIONAL& value)
	{
		Operator = std::make_shared<XCONDITIONAL_OPERATOR_URELATIONAL>(value);
	}
	//****************************************************************************************
	XCONDITIONAL_EXPRESSION::XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_BRELATIONAL& value)
	{
		Operator = std::make_shared<XCONDITIONAL_OPERATOR_BRELATIONAL>(value);
	}
	//****************************************************************************************
	XCONDITIONAL_EXPRESSION::XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_ULOGICAL& value)
	{
		Operator = std::make_shared<XCONDITIONAL_OPERATOR_ULOGICAL>(value);
	}
	//****************************************************************************************
	XCONDITIONAL_EXPRESSION::XCONDITIONAL_EXPRESSION(const XCONDITIONAL_OPERATOR_BLOGICAL& value)
	{
		Operator = std::make_shared<XCONDITIONAL_OPERATOR_BLOGICAL>(value);
	}
	//****************************************************************************************
	XCONDITIONAL_EXPRESSION::XCONDITIONAL_EXPRESSION(const bin_t& data)
	{
		#pragma region Check data header
		if((data[0] != 0x61) || (data[1] != 0x72) || (data[2] != 0x74) || (data[3] != 0x78))
			throw std::exception("XCONDITIONAL_EXPRESSION: invalid header");
		#pragma endregion

		#pragma region Initial variables
		std::stack<XCONDITIONAL_OPERATOR*> stack;

		auto iterator = data.begin() + 4;
		auto end = data.end();
		#pragma endregion

		Operator = XCONDITIONAL_EXPRESSION::ReadOperators(&iterator, end)[0];
	}
	//****************************************************************************************
	XCONDITIONAL_EXPRESSION::XCONDITIONAL_EXPRESSION(const msxml_et& xml)
	{
		msxml_nt list = xml->selectNodes(L"./node()");

		if(list->length != 1)
			throw std::exception("XCONDITIONAL_EXPRESSION: only a single element allowed in XML");

		Operator = XCONDITIONAL_EXPRESSION::ReadOperator(list->item[0]);
	}
	//****************************************************************************************
	XCONDITIONAL_EXPRESSION::operator bin_t()
	{
		if(nullptr == Operator)
			throw std::exception("XCONDITIONAL_EXPRESSION: initialize data first");

		bin_t result{ 0x61, 0x72, 0x74, 0x78 };
		bin_t bin = (bin_t)*Operator;
		std::copy(bin.begin(), bin.end(), std::back_inserter(result));

		return result;
	}
	//****************************************************************************************
	XCONDITIONAL_EXPRESSION::operator xml_t()
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XCONDITIONAL_EXPRESSION: invalid input XML");

			if(nullptr == Operator)
				throw std::exception("XCONDITIONAL_EXPRESSION: initialize data first");
			#pragma endregion

			#pragma region Root element
			msxml_et op = xml->createElement(std::wstring(root.value_or(L"ConditionalExpression")).c_str());
			if(nullptr == op)
				throw std::exception("XCONDITIONAL_EXPRESSION: cannot create root XML element");
			#pragma endregion

			#pragma region Operator
			op->appendChild(((xml_t)*Operator)(xml, std::nullopt));
			#pragma endregion

			return op;
		};
	}
	//****************************************************************************************
	std::vector<std::shared_ptr<XCONDITIONAL_OPERATOR>> XCONDITIONAL_EXPRESSION::ReadOperators(bin_t::const_iterator* iter, bin_t::const_iterator end, bool data_only)
	{
		#pragma region Initial variables
		std::vector<std::shared_ptr<XCONDITIONAL_OPERATOR>> result;
		std::stack<std::shared_ptr<XCONDITIONAL_OPERATOR>> stack;
		#pragma endregion

		#pragma region Main read operators loop
		while(*iter != end)
		{
			auto value = *((*iter)++);

			switch(value)
			{
				case 0x00:
					continue; // Padding data, just continue
				case 0x01: // Signed Int8 Type
				case 0x02: // Signed Int16 Type
				case 0x03: // Signed Int32 Type
				case 0x04: // Signed Int64 Type
					stack.push(std::make_shared<XCONDITIONAL_OPERATOR_INT>(iter, end, value));
					break;
				case 0x10: // XUnicode Type
				case 0xF8: // XLocal Attribute
				case 0xF9: // XUser Attribute
				case 0xFA: // XResource Attribute
				case 0xFB: // XDevice Attribute
					stack.push(std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(iter, end, value));
					break;
				case 0x18: // Octet String Type
					stack.push(std::make_shared<XCONDITIONAL_OPERATOR_OCTET>(iter, end));
					break;
				case 0x50: // XComposite Type
					stack.push(std::make_shared<XCONDITIONAL_OPERATOR_COMPOSITE>(iter, end));
					break;
				case 0x51: // SID Type
					stack.push(std::make_shared<XCONDITIONAL_OPERATOR_SID>(iter, end));
					break;
				default:
					{
						if(data_only)
							throw std::exception("XCONDITIONAL_EXPRESSION: invalid token value");

						switch(value)
						{
							case 0x89: // XMember_of
							case 0x8A: // XDevice_Member_of
							case 0x8B: // XMember_of_Any
							case 0x8C: // XDevice_Member_of_Any
							case 0x90: // XNot_Member_of
							case 0x91: // XNot_Device_Member_of
							case 0x92: // XNot_Member_of_Any
							case 0x93: // XNot_Device_Member_of_Any
								{
									if(0 == stack.size())
										throw std::exception("XCONDITIONAL_EXPRESSION: invalid data structure");

									auto top = stack.top();
									stack.pop();

									stack.push(std::make_shared<XCONDITIONAL_OPERATOR_URELATIONAL>(top, value));
								}
								break;
							case 0x80: // ==
							case 0x81: // !=
							case 0x82: // <
							case 0x83: // <=
							case 0x84: // >
							case 0x85: // >=
							case 0x86: // XContains
							case 0x88: // XAny_of
							case 0x8E: // XNot_Contains
							case 0x8F: // XNot_Any_of
								{
									if(stack.size() < 2)
										throw std::exception("XCONDITIONAL_EXPRESSION: invalid data structure");

									auto rhs = stack.top();
									stack.pop();

									auto lhs = stack.top();
									stack.pop();

									stack.push(std::make_shared<XCONDITIONAL_OPERATOR_BRELATIONAL>(lhs, rhs, value));
								}
								break;
							case 0x87: // XExists
							case 0x8D: // XNot_Exists
							case 0xA2: // Logical NOT (!)
								{
									if(0 == stack.size())
										throw std::exception("XCONDITIONAL_EXPRESSION: invalid data structure");

									auto top = stack.top();
									stack.pop();

									stack.push(std::make_shared<XCONDITIONAL_OPERATOR_ULOGICAL>(top, value));
								}
								break;
							case 0xA0: // Logical AND (&&)
							case 0xA1: // Logical OR (||)
								{
									if(stack.size() < 2)
										throw std::exception("XCONDITIONAL_EXPRESSION: invalid data structure");

									auto rhs = stack.top();
									stack.pop();

									auto lhs = stack.top();
									stack.pop();

									stack.push(std::make_shared<XCONDITIONAL_OPERATOR_BLOGICAL>(lhs, rhs, value));
								}
								break;
							default:
								throw std::exception("XCONDITIONAL_EXPRESSION: invalid token value");
						}
					}
			}
		}
		#pragma endregion

		#pragma region Fill result
		if((stack.size() > 1) && (false == data_only))
			throw std::exception("XCONDITIONAL_EXPRESSION: invalid conditional expression");

		while(!stack.empty())
		{
			result.push_back(stack.top());
			stack.pop();
		}
		#pragma endregion

		return result;
	}
	//****************************************************************************************
	std::shared_ptr<XCONDITIONAL_OPERATOR> XCONDITIONAL_EXPRESSION::ReadOperator(msxml_et xml, bool data_only)
	{
		#pragma region Initial variables
		std::shared_ptr<XCONDITIONAL_OPERATOR> Value;

		std::wstring Name = (wchar_t*)xml->nodeName;
		std::transform(Name.begin(), Name.end(), Name.begin(), ::toupper);
		#pragma endregion

		#pragma region XCONDITIONAL_OPERATOR_INT
		if((nullptr == Value) && XCONDITIONAL_OPERATOR_INT::Codes.count(Name))
		{
			auto find = XCONDITIONAL_OPERATOR_INT::Codes.find(Name);
			Value = std::make_shared<XCONDITIONAL_OPERATOR_INT>(xml, find->second);
		}
		#pragma endregion

		#pragma region XCONDITIONAL_OPERATOR_UNICODE
		if((nullptr == Value) && XCONDITIONAL_OPERATOR_UNICODE::Codes.count(Name))
		{
			auto find = XCONDITIONAL_OPERATOR_UNICODE::Codes.find(Name);
			Value = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(xml, find->second);
		}
		#pragma endregion

		#pragma region XCONDITIONAL_OPERATOR_OCTET
		if((nullptr == Value) && XCONDITIONAL_OPERATOR_OCTET::Codes.count(Name))
			Value = std::make_shared<XCONDITIONAL_OPERATOR_OCTET>(xml);
		#pragma endregion

		#pragma region XCONDITIONAL_OPERATOR_COMPOSITE
		if((nullptr == Value) && XCONDITIONAL_OPERATOR_COMPOSITE::Codes.count(Name))
			Value = std::make_shared<XCONDITIONAL_OPERATOR_COMPOSITE>(xml);
		#pragma endregion

		#pragma region XCONDITIONAL_OPERATOR_SID
		if((nullptr == Value) && XCONDITIONAL_OPERATOR_SID::Codes.count(Name))
			Value = std::make_shared<XCONDITIONAL_OPERATOR_SID>(xml);
		#pragma endregion

		if(false == data_only)
		{
			#pragma region XCONDITIONAL_OPERATOR_URELATIONAL
			if((nullptr == Value) && XCONDITIONAL_OPERATOR_URELATIONAL::Codes.count(Name))
			{
				auto find = XCONDITIONAL_OPERATOR_URELATIONAL::Codes.find(Name);
				Value = std::make_shared<XCONDITIONAL_OPERATOR_URELATIONAL>(xml, find->second);
			}
			#pragma endregion

			#pragma region XCONDITIONAL_OPERATOR_BRELATIONAL
			if((nullptr == Value) && XCONDITIONAL_OPERATOR_BRELATIONAL::Codes.count(Name))
			{
				auto find = XCONDITIONAL_OPERATOR_BRELATIONAL::Codes.find(Name);
				Value = std::make_shared<XCONDITIONAL_OPERATOR_BRELATIONAL>(xml, find->second);
			}
			#pragma endregion

			#pragma region XCONDITIONAL_OPERATOR_ULOGICAL
			if((nullptr == Value) && XCONDITIONAL_OPERATOR_ULOGICAL::Codes.count(Name))
			{
				auto find = XCONDITIONAL_OPERATOR_ULOGICAL::Codes.find(Name);
				Value = std::make_shared<XCONDITIONAL_OPERATOR_ULOGICAL>(xml, find->second);
			}
			#pragma endregion

			#pragma region XCONDITIONAL_OPERATOR_BLOGICAL
			if((nullptr == Value) && XCONDITIONAL_OPERATOR_BLOGICAL::Codes.count(Name))
			{
				auto find = XCONDITIONAL_OPERATOR_BLOGICAL::Codes.find(Name);
				Value = std::make_shared<XCONDITIONAL_OPERATOR_BLOGICAL>(xml, find->second);
			}
			#pragma endregion
		}

		if(nullptr == Value)
			throw std::exception("XCONDITIONAL_EXPRESSION: invalid input XML data");

		return Value;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Aux function for conditional expressions
	//****************************************************************************************
	using logical_operators = std::variant<
		XCONDITIONAL_OPERATOR_UNICODE, // Attributes only. Could be "bool" or "int" types. If type is "int" the "all not a 0 == true" (even if value < 0)
		XCONDITIONAL_OPERATOR_URELATIONAL,
		XCONDITIONAL_OPERATOR_BRELATIONAL,
		XCONDITIONAL_OPERATOR_ULOGICAL,
		XCONDITIONAL_OPERATOR_BLOGICAL
	>;
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT XSigned8(const int8_t& value)
	{
		return XCONDITIONAL_OPERATOR_INT(value, (unsigned char)0x01);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT XSigned16(const int16_t& value)
	{
		return XCONDITIONAL_OPERATOR_INT(value, (unsigned char)0x02);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT XSigned32(const int32_t& value)
	{
		return XCONDITIONAL_OPERATOR_INT(value, (unsigned char)0x03);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_INT XSigned64(const int64_t& value)
	{
		return XCONDITIONAL_OPERATOR_INT(value, (unsigned char)0x04);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE XUnicode(const std::wstring& string)
	{
		return XCONDITIONAL_OPERATOR_UNICODE(string, (unsigned char)0x10);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE XLocal(const std::wstring& string)
	{
		return XCONDITIONAL_OPERATOR_UNICODE(string, (unsigned char)0xF8);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE XUser(const std::wstring& string)
	{
		return XCONDITIONAL_OPERATOR_UNICODE(string, (unsigned char)0xF9);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE XResource(const std::wstring& string)
	{
		return XCONDITIONAL_OPERATOR_UNICODE(string, (unsigned char)0xFA);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_UNICODE XDevice(const std::wstring& string)
	{
		return XCONDITIONAL_OPERATOR_UNICODE(string, (unsigned char)0xFB);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_OCTET XOctetString(const bin_t& value)
	{
		return XCONDITIONAL_OPERATOR_OCTET(value);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_COMPOSITE XComposite(const XCONDITIONAL_OPERATOR_COMPOSITE::type& value)
	{
		return XCONDITIONAL_OPERATOR_COMPOSITE(value);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL XMember_of(const XCONDITIONAL_OPERATOR_URELATIONAL::type& value)
	{
		return XCONDITIONAL_OPERATOR_URELATIONAL(value, (unsigned char)0x89);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL XDevice_Member_of(const XCONDITIONAL_OPERATOR_URELATIONAL::type& value)
	{
		return XCONDITIONAL_OPERATOR_URELATIONAL(value, (unsigned char)0x8A);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL XMember_of_Any(const XCONDITIONAL_OPERATOR_URELATIONAL::type& value)
	{
		return XCONDITIONAL_OPERATOR_URELATIONAL(value, (unsigned char)0x8B);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL XDevice_Member_of_Any(const XCONDITIONAL_OPERATOR_URELATIONAL::type& value)
	{
		return XCONDITIONAL_OPERATOR_URELATIONAL(value, (unsigned char)0x8C);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL XNot_Member_of(const XCONDITIONAL_OPERATOR_URELATIONAL::type& value)
	{
		return XCONDITIONAL_OPERATOR_URELATIONAL(value, (unsigned char)0x90);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL XNot_Device_Member_of(const XCONDITIONAL_OPERATOR_URELATIONAL::type& value)
	{
		return XCONDITIONAL_OPERATOR_URELATIONAL(value, (unsigned char)0x91);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL XNot_Member_of_Any(const XCONDITIONAL_OPERATOR_URELATIONAL::type& value)
	{
		return XCONDITIONAL_OPERATOR_URELATIONAL(value, (unsigned char)0x92);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_URELATIONAL XNot_Device_Member_of_Any(const XCONDITIONAL_OPERATOR_URELATIONAL::type& value)
	{
		return XCONDITIONAL_OPERATOR_URELATIONAL(value, (unsigned char)0x93);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL XContains(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type2& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x86);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL XAny_of(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type2& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x88);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL XNot_Contains(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type2& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x8E);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL XNot_Any_of(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type2& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x8F);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_ULOGICAL XExists(const XCONDITIONAL_OPERATOR_UNICODE& value)
	{
		return XCONDITIONAL_OPERATOR_ULOGICAL(value, (unsigned char)0x87);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_ULOGICAL XNot_Exists(const XCONDITIONAL_OPERATOR_UNICODE& value)
	{
		return XCONDITIONAL_OPERATOR_ULOGICAL(value, (unsigned char)0x8D);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_ULOGICAL operator!(const logical_operators& value)
	{
		std::shared_ptr<XCONDITIONAL_OPERATOR> Value;

		std::visit([&](auto&& arg)
		{
			using T = std::decay_t<decltype(arg)>;

			if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_URELATIONAL>)
				Value = std::make_shared<XCONDITIONAL_OPERATOR_URELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BRELATIONAL>)
				Value = std::make_shared<XCONDITIONAL_OPERATOR_BRELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_ULOGICAL>)
				Value = std::make_shared<XCONDITIONAL_OPERATOR_ULOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BLOGICAL>)
				Value = std::make_shared<XCONDITIONAL_OPERATOR_BLOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_UNICODE>)
				Value = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(arg);
			}, value);

		return XCONDITIONAL_OPERATOR_ULOGICAL(Value, (unsigned char)0xA2);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL operator<(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type1& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x82);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL operator<=(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type1& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x83);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL operator>(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type1& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x84);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL operator>=(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type1& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x85);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL operator==(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type2& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x80);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BRELATIONAL operator!=(const XCONDITIONAL_OPERATOR_UNICODE& lhs, const XCONDITIONAL_OPERATOR_BRELATIONAL::type2& rhs)
	{
		return XCONDITIONAL_OPERATOR_BRELATIONAL(lhs, rhs, (unsigned char)0x81);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BLOGICAL operator&&(const logical_operators& lhs, const logical_operators& rhs)
	{
		std::shared_ptr<XCONDITIONAL_OPERATOR> LHS;
		std::shared_ptr<XCONDITIONAL_OPERATOR> RHS;

		std::visit([&](auto&& arg)
		{
			using T = std::decay_t<decltype(arg)>;

			if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_URELATIONAL>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_URELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BRELATIONAL>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_BRELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_ULOGICAL>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_ULOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BLOGICAL>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_BLOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_UNICODE>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(arg);
		}, lhs);

		std::visit([&](auto&& arg)
		{
			using T = std::decay_t<decltype(arg)>;

			if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_URELATIONAL>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_URELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BRELATIONAL>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_BRELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_ULOGICAL>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_ULOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BLOGICAL>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_BLOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_UNICODE>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(arg);
		}, rhs);

		return XCONDITIONAL_OPERATOR_BLOGICAL(LHS, RHS, (unsigned char)0xA0);
	}
	//****************************************************************************************
	XCONDITIONAL_OPERATOR_BLOGICAL operator||(const logical_operators& lhs, const logical_operators& rhs)
	{
		std::shared_ptr<XCONDITIONAL_OPERATOR> LHS;
		std::shared_ptr<XCONDITIONAL_OPERATOR> RHS;

		std::visit([&](auto&& arg)
		{
			using T = std::decay_t<decltype(arg)>;

			if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_URELATIONAL>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_URELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BRELATIONAL>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_BRELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_ULOGICAL>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_ULOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BLOGICAL>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_BLOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_UNICODE>)
				LHS = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(arg);
		}, lhs);

		std::visit([&](auto&& arg)
		{
			using T = std::decay_t<decltype(arg)>;

			if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_URELATIONAL>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_URELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BRELATIONAL>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_BRELATIONAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_ULOGICAL>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_ULOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_BLOGICAL>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_BLOGICAL>(arg);
			else if constexpr(std::is_same_v<T, XCONDITIONAL_OPERATOR_UNICODE>)
				RHS = std::make_shared<XCONDITIONAL_OPERATOR_UNICODE>(arg);
		}, rhs);

		return XCONDITIONAL_OPERATOR_BLOGICAL(LHS, RHS, (unsigned char)0xA1);
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
};
//********************************************************************************************

