/*
	MIT License

	Copyright (c) 2020 Oleksiy Ryabchun

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

#pragma once

#include "IHooker.h"

class Hooker : public IHooker {
private:
	HMODULE hModule;
	PIMAGE_NT_HEADERS headNT;
	DWORD baseOffset;
	VOID* mapAddress;
	HANDLE hFile;
	HANDLE hMap;

	BOOL MapFile();
	VOID UnmapFile();

public:
	VOID* operator new(size_t);
	VOID operator delete(VOID*);

	Hooker(HMODULE);
	~Hooker();

	VOID Release();

	DWORD GetBaseOffset();
	HMODULE GetModuleHandle();

	BOOL ReadBlock(DWORD, VOID*, DWORD);
	BOOL ReadByte(DWORD, BYTE*);
	BOOL ReadWord(DWORD, WORD*);
	BOOL ReadDWord(DWORD, DWORD*);
	BOOL PatchRedirect(DWORD, DWORD, RedirectType, DWORD = 0);
	BOOL PatchJump(DWORD, DWORD);
	BOOL PatchHook(DWORD, VOID*, DWORD = 0);
	BOOL PatchCall(DWORD, VOID*, DWORD = 0);
	BOOL PatchSet(DWORD, BYTE, DWORD);
	BOOL PatchNop(DWORD, DWORD);
	BOOL PatchBlock(DWORD, VOID*, DWORD);
	BOOL PatchByte(DWORD, BYTE);
	BOOL PatchWord(DWORD, WORD);
	BOOL PatchDWord(DWORD, DWORD);
	DWORD PatchImport(const CHAR*, VOID*);
	DWORD PatchExport(const CHAR*, VOID*);
	DWORD PatchEntry(VOID*);
};
