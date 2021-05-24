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

#pragma comment(lib, "Secur32.lib")

#include <array>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <bitset>
#include <functional>
#include <variant>
#include <sstream>
#include <iomanip>
#include <stack>
#include <map>
#include <algorithm>
#include <regex>

#include <windows.h>
#include <winnt.h>

#import <msxml6.dll>

#include "./common.h"
#include "./bitset.h"
#include "./sid.h"
#include "./auxl.h"
#include "./claims.h"
#include "./expression.h"
#include "./ace.h"
#include "./acl.h"
#include "./sd.h"
#include "./token.h"