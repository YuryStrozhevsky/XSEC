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
	#pragma region Common types
	using msxml_et = MSXML2::IXMLDOMElementPtr;
	using msxml_dt = MSXML2::IXMLDOMDocumentPtr;
	using msxml_at = MSXML2::IXMLDOMAttributePtr;
	using msxml_nt = MSXML2::IXMLDOMNodeListPtr;
	template<typename T> using IL = std::initializer_list<T>;

	using xml_t = std::function<auto (msxml_dt, std::optional<const wchar_t*>)->msxml_et>;
	using bin_t = std::vector<unsigned char>;
	#pragma endregion

	#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

	#pragma region Different guards
	struct new_guard
	{
		new_guard(void* _value) : value(_value) {};
		~new_guard()
		{
			if(nullptr != value)
				delete value;
		}

		private:
		void* value = nullptr;
	};

	struct thread_guard
	{
		thread_guard(HANDLE _value) : value(_value) 
		{
			if(FALSE == SetThreadToken(nullptr, value))
				throw std::exception("Cannot execute 'SetThreadToken'");
		};
		~thread_guard()
		{
			if(nullptr != value)
			{
				CloseHandle(value);
				SetThreadToken(nullptr, nullptr);
			}
		}

		private:
		HANDLE value = nullptr;
	};

	struct token_guard
	{
		token_guard(HANDLE _value) : value(_value) {}
		~token_guard()
		{
			if(nullptr != value)
				CloseHandle(value);
		};

	private:
		HANDLE value = nullptr;
	};
	#pragma endregion
	//********************************************************************************************
	#pragma region Common functions
	//********************************************************************************************
	std::string hex_codes(std::vector<unsigned char> value)
	{
		std::stringstream stream;
		stream << std::uppercase << std::setfill('0') << std::hex;

		// In it hard to use "std::copy" here due to fact that "setw" flag is not preserved
		for(unsigned char element : value)
		{
			if((size_t)stream.tellp())
				stream << " ";

			stream << std::setw(2) << (int)element;
		}

		return stream.str();
	}
	//********************************************************************************************
	std::wstring whex_codes(std::vector<unsigned char> value)
	{
		std::wstringstream stream;
		stream << std::uppercase << std::setfill(L'0') << std::hex;

		// In it hard to use "std::copy" here due to fact that "setw" flag is not preserved
		for(unsigned char element : value)
		{
			if((size_t)stream.tellp())
				stream << L" ";

			stream << std::setw(2) << (int)element;
		}

		return stream.str();
	}
	//********************************************************************************************
	std::vector<unsigned char> from_hex_codes(std::string value)
	{
		std::vector<unsigned char> result;

		std::stringstream stream(value);
		stream >> std::hex;

		std::copy(std::istream_iterator<int>(stream), std::istream_iterator<int>(), std::back_inserter(result));

		return result;
	}
	//********************************************************************************************
	std::vector<unsigned char> from_hex_codes(std::wstring value)
	{
		std::vector<unsigned char> result;

		std::wstringstream stream(value);
		stream >> std::hex;

		std::copy(std::istream_iterator<int, wchar_t>(stream), std::istream_iterator<int, wchar_t>(), std::back_inserter(result));

		return result;
	}
	//********************************************************************************************
	DWORD dword_vec(std::vector<unsigned char> value)
	{
		DWORD result = 0;
		unsigned char i = 0;

		for(auto&& element : value)
		{
			((BYTE*)&result)[i++] = element;

			if(i == 4)
				break;
		}

		return result;
	}
	//********************************************************************************************
	unsigned char byte_vec(std::vector<unsigned char> value)
	{
		return (value.size()) ? value[0] : 0;
	}
	//********************************************************************************************
	unsigned short word_vec(std::vector<unsigned char> value)
	{
		unsigned short result = 0;
		unsigned char i = 0;

		for(auto&& element : value)
		{
			((BYTE*)&result)[i++] = element;

			if(i == 2)
				break;
		}

		return result;
	}
	//********************************************************************************************
	std::vector<unsigned char> vec_dword(DWORD value)
	{
		std::vector<unsigned char> result;

		result.push_back(((BYTE*)&value)[0]);
		result.push_back(((BYTE*)&value)[1]);
		result.push_back(((BYTE*)&value)[2]);
		result.push_back(((BYTE*)&value)[3]);

		return result;
	}
	//********************************************************************************************
	std::vector<unsigned char> vec_byte(unsigned char value)
	{
		return std::vector<unsigned char>{ value };
	}
	//********************************************************************************************
	std::vector<unsigned char> vec_word(unsigned short value)
	{
		std::vector<unsigned char> result;

		result.push_back(((BYTE*)&value)[0]);
		result.push_back(((BYTE*)&value)[1]);

		return result;
	}
	//********************************************************************************************
	template<typename T>
	void XSave(const T& element, const std::wstring& path)
	{
		MSXML2::IXMLDOMDocument2Ptr xml;
		xml.CreateInstance(__uuidof(MSXML2::DOMDocument60), NULL, CLSCTX_INPROC_SERVER);

		xml->documentElement = ((xml_t)element)(xml, std::nullopt);
		xml->save(path.c_str());
	}
	//********************************************************************************************
	template<typename T>
	void XSave_bin(const T& element, const std::string& path)
	{
		std::ofstream file(path, std::ios_base::binary);
		std::ostream_iterator<char> _out_iterator(file);

		auto data = (bin_t)element;
		std::copy(data.data(), data.data() + data.size(), *_out_iterator);

		file.flush();
		file.close();
	}
	//********************************************************************************************
	template<typename T, typename... Types>
	T XLoad(const std::wstring& path, Types&&... args)
	{
		MSXML2::IXMLDOMDocument2Ptr xml;
		xml.CreateInstance(__uuidof(MSXML2::DOMDocument60), NULL, CLSCTX_INPROC_SERVER);

		xml->async = VARIANT_FALSE;
		xml->validateOnParse = VARIANT_FALSE;

		VARIANT_BOOL result = xml->load(path.c_str());
		if(VARIANT_FALSE == result)
			throw std::exception("XLoad: cannot load from XML");

		// There is a compiler error, at least in VS 16.9.4, and in order to have
		// correct type user needs to pass all default parameters here
		return T(xml->documentElement, std::forward<Types>(args)...);
	}
	//********************************************************************************************
	#pragma endregion
	//********************************************************************************************
};
//********************************************************************************************