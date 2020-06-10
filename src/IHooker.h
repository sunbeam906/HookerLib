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
#pragma comment(lib, "hooker.lib")
#pragma comment(linker, "/DLL /ENTRY:HookMain@12")

enum RedirectType
{
	REDIRECT_CALL = 0xE8,
	REDIRECT_JUMP = 0xE9,
	REDIRECT_JUMP_SHORT = 0xEB
};

class IHooker {
public:
	/// <summary>
	/// Deletes Hooker object
	/// </summary>
	virtual VOID Release();

	/// <summary>
	/// Retrives module base address offset
	/// </summary>
	/// <returns></returns>
	virtual DWORD GetBaseOffset();

	/// <summary>
	/// Retrives module handle
	/// </summary>
	/// <returns></returns>
	virtual HMODULE GetModuleHandle();

	/// <summary>
	/// Reads data block
	/// </summary>
	/// <param name="address"></param>
	/// <param name="block"></param>
	/// <param name="size"></param>
	/// <returns></returns>
	virtual BOOL ReadBlock(DWORD address, VOID* block, DWORD size);

	/// <summary>
	/// Reads byte value
	/// </summary>
	/// <param name="address"></param>
	/// <param name="lpValue"></param>
	/// <returns></returns>
	virtual BOOL ReadByte(DWORD address, BYTE* lpValue);

	/// <summary>
	/// Reads word value
	/// </summary>
	/// <param name="address"></param>
	/// <param name="lpValue"></param>
	/// <returns></returns>
	virtual BOOL ReadWord(DWORD address, WORD* lpValue);

	/// <summary>
	/// Reads double word value
	/// </summary>
	/// <param name="address"></param>
	/// <param name="lpValue"></param>
	/// <returns></returns>
	virtual BOOL ReadDWord(DWORD address, DWORD* lpValue);

	/// <summary>
	/// Write redirect to new address
	/// </summary>
	/// <param name="address"></param>
	/// <param name="newAddress"></param>
	/// <param name="type"></param>
	/// <param name="nopCount"></param>
	/// <returns></returns>
	virtual BOOL PatchRedirect(DWORD address, DWORD newAddress, RedirectType type, DWORD nopCount = 0);

	/// <summary>
	/// Writes jump to new address
	/// </summary>
	/// <param name="address"></param>
	/// <param name="jumpAddress"></param>
	/// <returns></returns>
	virtual BOOL PatchJump(DWORD address, DWORD jumpAddress);

	/// <summary>
	/// Writes jump to new function
	/// </summary>
	/// <param name="address"></param>
	/// <param name="hookAddress"></param>
	/// <param name="nopCount"></param>
	/// <returns></returns>
	virtual BOOL PatchHook(DWORD address, VOID* hookAddress, DWORD nopCount = 0);

	/// <summary>
	/// Writes call to new function
	/// </summary>
	/// <param name="address"></param>
	/// <param name="funcAddress"></param>
	/// <param name="nopCount"></param>
	/// <returns></returns>
	virtual BOOL PatchCall(DWORD address, VOID* funcAddress, DWORD nopCount = 0);

	/// <summary>
	/// Fill bytes by specified value
	/// </summary>
	/// <param name="address"></param>
	/// <param name="value"></param>
	/// <param name="size"></param>
	/// <returns></returns>
	virtual BOOL PatchSet(DWORD address, BYTE value, DWORD size);

	/// <summary>
	/// Fills bytes by no operation (nop) instruction
	/// </summary>
	/// <param name="address"></param>
	/// <param name="size"></param>
	/// <returns></returns>
	virtual BOOL PatchNop(DWORD address, DWORD size);

	/// <summary>
	/// Writes new data block
	/// </summary>
	/// <param name="address"></param>
	/// <param name="block"></param>
	/// <param name="size"></param>
	/// <returns></returns>
	virtual BOOL PatchBlock(DWORD address, VOID* block, DWORD size);

	/// <summary>
	/// Writes new byte value
	/// </summary>
	/// <param name="address"></param>
	/// <param name="value"></param>
	/// <returns></returns>
	virtual BOOL PatchByte(DWORD address, BYTE value);

	/// <summary>
	/// Writes new word value
	/// </summary>
	/// <param name="address"></param>
	/// <param name="value"></param>
	/// <returns></returns>
	virtual BOOL PatchWord(DWORD address, WORD value);

	/// <summary>
	/// Writes new double word value
	/// </summary>
	/// <param name="address"></param>
	/// <param name="value"></param>
	/// <returns></returns>
	virtual BOOL PatchDWord(DWORD address, DWORD value);

	/// <summary>
	/// Redirects module imported function and retrives old address
	/// </summary>
	/// <param name="funcName"></param>
	/// <param name="funcAddress"></param>
	/// <returns></returns>
	virtual DWORD PatchImport(const CHAR* funcName, VOID* funcAddress);

	/// <summary>
	/// Redirects module exported function and retrives old address
	/// </summary>
	/// <param name="funcName"></param>
	/// <param name="funcAddress"></param>
	/// <returns></returns>
	virtual DWORD PatchExport(const CHAR* funcName, VOID* funcAddress);

	/// <summary>
	/// Redirects module entry point and retrives old address
	/// </summary>
	/// <param name="funcAddress"></param>
	/// <returns></returns>
	virtual DWORD PatchEntry(VOID* funcAddress);
};

IHooker* CreateHooker(HMODULE hModule);
