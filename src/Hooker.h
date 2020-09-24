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

enum RedirectType
{
	REDIRECT_CALL = 0xE8,
	REDIRECT_JUMP = 0xE9,
	REDIRECT_JUMP_SHORT = 0xEB
};

//typedef VOID* HOOKER;

typedef struct Hooker {
	HANDLE hHeap;
	HMODULE hModule;
	PIMAGE_NT_HEADERS headNT;
	DWORD baseOffset;
	VOID* mapAddress;
	HANDLE hFile;
	HANDLE hMap;
} * HOOKER;

extern "C"
{
	BOOL MapFile(HOOKER);
	VOID UnmapFile(HOOKER);
	VOID CreateInner(HOOKER, HANDLE, HMODULE);
	VOID ReleaseInner(HOOKER);

	HOOKER CreateHooker(HMODULE);
	VOID ReleaseHooker(HOOKER);
	DWORD GetBaseOffset(HOOKER);
	HMODULE GetHookerModule(HOOKER);
	BOOL ReadBlock(HOOKER, DWORD, VOID*, DWORD);
	BOOL ReadByte(HOOKER, DWORD, BYTE*);
	BOOL ReadWord(HOOKER, DWORD, WORD*);
	BOOL ReadDWord(HOOKER, DWORD, DWORD*);
	DWORD FindBlock(HOOKER, VOID*, DWORD, DWORD = 0, DWORD = 0);
	DWORD FindCall(HOOKER, DWORD, DWORD =0 , DWORD = 0);
	BOOL PatchRedirect(HOOKER, DWORD, DWORD, RedirectType, DWORD = 0);
	BOOL PatchJump(HOOKER, DWORD, DWORD);
	BOOL PatchHex(HOOKER, DWORD, CHAR*);
	BOOL PatchBlock(HOOKER, DWORD, VOID*, DWORD);
	BOOL PatchHook(HOOKER, DWORD, VOID*, DWORD = 0);
	BOOL PatchCall(HOOKER, DWORD, VOID*, DWORD = 0);
	BOOL PatchSet(HOOKER, DWORD, BYTE, DWORD);
	BOOL PatchNop(HOOKER, DWORD, DWORD);
	BOOL PatchByte(HOOKER, DWORD, BYTE);
	BOOL PatchWord(HOOKER, DWORD, WORD);
	BOOL PatchDWord(HOOKER, DWORD, DWORD);
	DWORD RedirectCall(HOOKER, DWORD, VOID*);
	DWORD PatchImport(HOOKER, const CHAR*, VOID*, DWORD* = NULL);
	DWORD PatchExport(HOOKER, const CHAR*, VOID*, DWORD* = NULL);
	DWORD PatchEntry(HOOKER, VOID*);
	VOID RedirectImports(HOOKER, const CHAR*, HMODULE);
}