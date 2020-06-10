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

#include "windows.h"
#include "Hooker.h"

#pragma optimize("t", on)
extern "C"
{
	VOID __declspec(naked) __stdcall mcpy(VOID* dst, const VOID* src, DWORD len)
	{
		__asm {
			push ebp
			mov ebp, esp
			push esi
			push edi

			mov esi, src
			mov edi, dst
			mov ecx, len
			rep movsb
			
			pop edi
			pop esi
			mov esp, ebp
			pop ebp
			retn 12
		}
	}

	VOID __declspec(naked) __stdcall mset(VOID* dst, DWORD val, DWORD len)
	{
		__asm {
			push ebp
			mov ebp, esp
			push edi

			mov edi, dst
			mov eax, val
			mov ecx, len
			rep stosb
			
			pop edi
			mov esp, ebp
			pop ebp
			retn 12
		}
	}

	BOOL __inline scmp(const CHAR* str1, const CHAR* str2)
	{
		while (*str1 == *str2)
		{
			if (!*str1)
				return FALSE;

			++str1;
			++str2;
		}

		return TRUE;
	}
}

#pragma optimize("s", on)
VOID* Hooker::operator new(size_t size)
{
	return HeapAlloc(GetProcessHeap(), NULL, size);
}

VOID Hooker::operator delete(VOID* p)
{
	HeapFree(GetProcessHeap(), NULL, p);
}

Hooker::Hooker(HMODULE hModule)
{
	this->hModule = hModule;
	this->headNT = (PIMAGE_NT_HEADERS)((DWORD)this->hModule + ((PIMAGE_DOS_HEADER)this->hModule)->e_lfanew);
	this->baseOffset = (INT)this->hModule - (INT)this->headNT->OptionalHeader.ImageBase;

	this->hFile = INVALID_HANDLE_VALUE;
	this->hMap = NULL;
	this->mapAddress = NULL;
}

Hooker::~Hooker()
{
	this->UnmapFile();
}

VOID Hooker::Release()
{
	delete this;
}

DWORD Hooker::GetBaseOffset()
{
	return this->baseOffset;
}

HMODULE Hooker::GetModuleHandle()
{
	return this->hModule;
}

BOOL Hooker::MapFile()
{
	if (!this->mapAddress)
	{
		if (this->hFile == INVALID_HANDLE_VALUE)
		{
			CHAR filePath[MAX_PATH];
			GetModuleFileName(this->hModule, filePath, MAX_PATH);
			this->hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (this->hFile == INVALID_HANDLE_VALUE)
				return FALSE;
		}

		if (!this->hMap)
		{
			this->hMap = CreateFileMapping(this->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
			if (!this->hMap)
				return FALSE;
		}

		this->mapAddress = MapViewOfFile(this->hMap, FILE_MAP_READ, 0, 0, 0);
	}

	return (BOOL)this->mapAddress;
}

VOID Hooker::UnmapFile()
{
	if (this->mapAddress && UnmapViewOfFile(this->mapAddress))
		this->mapAddress = NULL;

	if (this->hMap && CloseHandle(this->hMap))
		this->hMap = NULL;

	if (this->hFile != INVALID_HANDLE_VALUE && CloseHandle(this->hFile))
		this->hFile = INVALID_HANDLE_VALUE;
}

BOOL Hooker::ReadBlock(DWORD addr, VOID* block, DWORD size)
{
	DWORD address = addr + this->baseOffset;

	DWORD old_prot;
	if (VirtualProtect((VOID*)address, size, PAGE_READONLY, &old_prot))
	{
		switch (size)
		{
		case 4:
			*(DWORD*)block = *(DWORD*)address;
			break;
		case 2:
			*(WORD*)block = *(WORD*)address;
			break;
		case 1:
			*(BYTE*)block = *(BYTE*)address;
			break;
		default:
			mcpy(block, (VOID*)address, size);
			break;
		}

		VirtualProtect((VOID*)address, size, old_prot, &old_prot);

		return TRUE;
	}
	return FALSE;
}

BOOL Hooker::ReadByte(DWORD addr, BYTE* value)
{
	return this->ReadBlock(addr, value, sizeof(*value));
}

BOOL Hooker::ReadWord(DWORD addr, WORD* value)
{
	return this->ReadBlock(addr, value, sizeof(*value));
}

BOOL Hooker::ReadDWord(DWORD addr, DWORD* value)
{
	return this->ReadBlock(addr, value, sizeof(*value));
}

BOOL Hooker::PatchRedirect(DWORD addr, DWORD dest, RedirectType type, DWORD nop)
{
	DWORD address = addr + this->baseOffset;

	DWORD size = type == REDIRECT_JUMP_SHORT ? 2 : 5;

	DWORD old_prot;
	if (VirtualProtect((VOID*)address, size + nop, PAGE_EXECUTE_READWRITE, &old_prot))
	{
		BYTE* jump = (BYTE*)address;
		*jump = LOBYTE(type);
		++jump;
		*(DWORD*)jump = dest - address - size;

		if (nop)
			mset((VOID*)(address + size), 0x90, nop);

		VirtualProtect((VOID*)address, size + nop, old_prot, &old_prot);

		return TRUE;
	}
	return FALSE;
}

BOOL Hooker::PatchJump(DWORD addr, DWORD dest)
{
	INT relative = dest - addr - this->baseOffset - 2;
	return this->PatchRedirect(addr, dest, relative >= -128 && relative <= 127 ? REDIRECT_JUMP_SHORT : REDIRECT_JUMP, 0);
}

BOOL Hooker::PatchHook(DWORD addr, VOID* hook, DWORD nop)
{
	return this->PatchRedirect(addr, (DWORD)hook, REDIRECT_JUMP, nop);
}

BOOL Hooker::PatchCall(DWORD addr, VOID* hook, DWORD nop)
{
	return this->PatchRedirect(addr, (DWORD)hook, REDIRECT_CALL, nop);
}

BOOL Hooker::PatchSet(DWORD addr, BYTE byte, DWORD size)
{
	DWORD address = addr + this->baseOffset;

	DWORD old_prot;
	if (VirtualProtect((VOID*)address, size, PAGE_EXECUTE_READWRITE, &old_prot))
	{
		mset((VOID*)address, byte, size);
		VirtualProtect((VOID*)address, size, old_prot, &old_prot);

		return TRUE;
	}
	return FALSE;
}

BOOL Hooker::PatchNop(DWORD addr, DWORD size)
{
	return this->PatchSet(addr, 0x90, size);
}

BOOL Hooker::PatchBlock(DWORD addr, VOID* block, DWORD size)
{
	DWORD address = addr + this->baseOffset;

	DWORD old_prot;
	if (VirtualProtect((VOID*)address, size, PAGE_EXECUTE_READWRITE, &old_prot))
	{
		switch (size)
		{
		case 4:
			*(DWORD*)address = *(DWORD*)block;
			break;
		case 2:
			*(WORD*)address = *(WORD*)block;
			break;
		case 1:
			*(BYTE*)address = *(BYTE*)block;
			break;
		default:
			mcpy((VOID*)address, block, size);
			break;
		}

		VirtualProtect((VOID*)address, size, old_prot, &old_prot);

		return TRUE;
	}
	return FALSE;
}

BOOL Hooker::PatchByte(DWORD addr, BYTE value)
{
	return this->PatchBlock(addr, &value, sizeof(value));
}

BOOL Hooker::PatchWord(DWORD addr, WORD value)
{
	return this->PatchBlock(addr, &value, sizeof(value));
}

BOOL Hooker::PatchDWord(DWORD addr, DWORD value)
{
	return this->PatchBlock(addr, &value, sizeof(value));
}

DWORD Hooker::PatchImport(const CHAR* function, VOID* addr)
{
	PIMAGE_DATA_DIRECTORY dataDir = &this->headNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (dataDir->Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)this->hModule + dataDir->VirtualAddress);
		for (DWORD idx = 0; imports->Name; ++idx, ++imports)
		{
			PIMAGE_THUNK_DATA addressThunk = (PIMAGE_THUNK_DATA)((DWORD)this->hModule + imports->FirstThunk);
			PIMAGE_THUNK_DATA nameThunk;
			if (imports->OriginalFirstThunk)
				nameThunk = (PIMAGE_THUNK_DATA)((DWORD)this->hModule + imports->OriginalFirstThunk);
			else if (this->MapFile())
			{
				PIMAGE_NT_HEADERS headNT = (PIMAGE_NT_HEADERS)((DWORD)this->mapAddress + ((PIMAGE_DOS_HEADER)this->mapAddress)->e_lfanew);
				PIMAGE_SECTION_HEADER sh = (PIMAGE_SECTION_HEADER)((DWORD)&headNT->OptionalHeader + headNT->FileHeader.SizeOfOptionalHeader);

				nameThunk = NULL;
				DWORD sCount = headNT->FileHeader.NumberOfSections;
				while (sCount--)
				{
					if (imports->FirstThunk >= sh->VirtualAddress && imports->FirstThunk < sh->VirtualAddress + sh->Misc.VirtualSize)
					{
						nameThunk = PIMAGE_THUNK_DATA((DWORD)this->mapAddress + sh->PointerToRawData + imports->FirstThunk - sh->VirtualAddress);
						break;
					}

					++sh;
				}

				if (!nameThunk)
					return NULL;
			}
			else
				return NULL;

			for (; nameThunk->u1.AddressOfData; ++nameThunk, ++addressThunk)
			{
				PIMAGE_IMPORT_BY_NAME name = PIMAGE_IMPORT_BY_NAME((DWORD)this->hModule + nameThunk->u1.AddressOfData);

				WORD hint;
				if (this->ReadWord((INT)name - this->baseOffset, &hint) && !scmp((CHAR*)name->Name, function))
				{
					DWORD res;
					if (this->ReadDWord((INT)&addressThunk->u1.AddressOfData - this->baseOffset, &res))
					{
						this->PatchDWord((INT)&addressThunk->u1.AddressOfData - this->baseOffset, (DWORD)addr);
						return res;
					}

					return NULL;
				}
			}
		}
	}

	return NULL;
}

DWORD Hooker::PatchExport(const CHAR* function, VOID* addr)
{
	DWORD func = (DWORD)GetProcAddress(this->hModule, function);
	if (func)
	{
		PIMAGE_DATA_DIRECTORY dataDir = &this->headNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (dataDir->Size)
		{
			PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((DWORD)this->hModule + dataDir->VirtualAddress);
			{
				DWORD* functions = (DWORD*)((DWORD)this->hModule + exports->AddressOfFunctions);

				for (DWORD i = 0; i < exports->NumberOfFunctions; ++i)
					if (func == (DWORD)this->hModule + functions[i])
						return this->PatchDWord((DWORD)&functions[i] - this->baseOffset, (DWORD)addr - (DWORD)this->hModule);
			}
		}
	}

	return NULL;
}

DWORD Hooker::PatchEntry(VOID* entryPoint)
{
	return this->PatchHook((DWORD)this->hModule + this->headNT->OptionalHeader.AddressOfEntryPoint, entryPoint);
}
#pragma optimize("", on)