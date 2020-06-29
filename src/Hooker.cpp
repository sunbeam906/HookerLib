/*
	MIT License

	Copyright (c) 2020 Oleksiy Ryabchun

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of hooker software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and hooker permission notice shall be included in all
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
	VOID __declspec(naked) MemoryCopy(VOID* dst, const VOID* src, DWORD len)
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

	VOID __declspec(naked) MemorySet(VOID* dst, DWORD val, DWORD len)
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

	BOOL __inline StrCompare(const CHAR* str1, const CHAR* str2)
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
BOOL MapFile(HOOKER hooker)
{
	if (!hooker->mapAddress)
	{
		if (hooker->hFile == INVALID_HANDLE_VALUE)
		{
			CHAR filePath[MAX_PATH];
			GetModuleFileName(hooker->hModule, filePath, MAX_PATH);
			hooker->hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hooker->hFile == INVALID_HANDLE_VALUE)
				return FALSE;
		}

		if (!hooker->hMap)
		{
			hooker->hMap = CreateFileMapping(hooker->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
			if (!hooker->hMap)
				return FALSE;
		}

		hooker->mapAddress = MapViewOfFile(hooker->hMap, FILE_MAP_READ, 0, 0, 0);
	}

	return (BOOL)hooker->mapAddress;
}

VOID UnmapFile(HOOKER hooker)
{
	if (hooker->mapAddress && UnmapViewOfFile(hooker->mapAddress))
		hooker->mapAddress = NULL;

	if (hooker->hMap && CloseHandle(hooker->hMap))
		hooker->hMap = NULL;

	if (hooker->hFile != INVALID_HANDLE_VALUE && CloseHandle(hooker->hFile))
		hooker->hFile = INVALID_HANDLE_VALUE;
}

VOID CreateInner(HOOKER hooker, HANDLE hHeap, HMODULE hModule)
{
	hooker->hHeap = hHeap;
	hooker->hModule = hModule;
	hooker->headNT = (PIMAGE_NT_HEADERS)((DWORD)hooker->hModule + ((PIMAGE_DOS_HEADER)hooker->hModule)->e_lfanew);
	hooker->baseOffset = (INT)hooker->hModule - (INT)hooker->headNT->OptionalHeader.ImageBase;

	hooker->hFile = INVALID_HANDLE_VALUE;
	hooker->hMap = NULL;
	hooker->mapAddress = NULL;
}

VOID ReleaseInner(HOOKER hooker)
{
	UnmapFile(hooker);
}

HOOKER CreateHooker(HMODULE hModule)
{
	HANDLE hHeap = GetProcessHeap();
	HOOKER hooker = (HOOKER)HeapAlloc(hHeap, NULL, sizeof(Hooker));
	if (hooker)
		CreateInner(hooker, hHeap, hModule);

	return hooker;
}

VOID ReleaseHooker(HOOKER hooker)
{
	ReleaseInner(hooker);
	HeapFree(hooker->hHeap, NULL, hooker);
}

DWORD GetBaseOffset(HOOKER hooker)
{
	return hooker->baseOffset;
}

HMODULE GetHookerHandle(HOOKER hooker)
{
	return hooker->hModule;
}

BOOL ReadBlock(HOOKER hooker, DWORD addr, VOID* block, DWORD size)
{
	DWORD address = addr + hooker->baseOffset;

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
			MemoryCopy(block, (VOID*)address, size);
			break;
		}

		VirtualProtect((VOID*)address, size, old_prot, &old_prot);

		return TRUE;
	}
	return FALSE;
}

BOOL ReadByte(HOOKER hooker, DWORD addr, BYTE* value)
{
	return ReadBlock(hooker, addr, value, sizeof(*value));
}

BOOL ReadWord(HOOKER hooker, DWORD addr, WORD* value)
{
	return ReadBlock(hooker, addr, value, sizeof(*value));
}

BOOL ReadDWord(HOOKER hooker, DWORD addr, DWORD* value)
{
	return ReadBlock(hooker, addr, value, sizeof(*value));
}

BOOL PatchRedirect(HOOKER hooker, DWORD addr, DWORD dest, RedirectType type, DWORD nop)
{
	DWORD address = addr + hooker->baseOffset;

	DWORD size = type == REDIRECT_JUMP_SHORT ? 2 : 5;

	DWORD old_prot;
	if (VirtualProtect((VOID*)address, size + nop, PAGE_EXECUTE_READWRITE, &old_prot))
	{
		BYTE* jump = (BYTE*)address;
		*jump = LOBYTE(type);
		++jump;
		*(DWORD*)jump = dest - address - size;

		if (nop)
			MemorySet((VOID*)(address + size), 0x90, nop);

		VirtualProtect((VOID*)address, size + nop, old_prot, &old_prot);

		return TRUE;
	}
	return FALSE;
}

BOOL PatchJump(HOOKER hooker, DWORD addr, DWORD dest)
{
	INT relative = dest - addr - hooker->baseOffset - 2;
	return PatchRedirect(hooker, addr, dest, relative >= -128 && relative <= 127 ? REDIRECT_JUMP_SHORT : REDIRECT_JUMP, 0);
}

BOOL PatchHook(HOOKER hooker, DWORD addr, VOID* hook, DWORD nop)
{
	return PatchRedirect(hooker, addr, (DWORD)hook, REDIRECT_JUMP, nop);
}

BOOL PatchCall(HOOKER hooker, DWORD addr, VOID* hook, DWORD nop)
{
	return PatchRedirect(hooker, addr, (DWORD)hook, REDIRECT_CALL, nop);
}

BOOL PatchSet(HOOKER hooker, DWORD addr, BYTE byte, DWORD size)
{
	DWORD address = addr + hooker->baseOffset;

	DWORD old_prot;
	if (VirtualProtect((VOID*)address, size, PAGE_EXECUTE_READWRITE, &old_prot))
	{
		MemorySet((VOID*)address, byte, size);
		VirtualProtect((VOID*)address, size, old_prot, &old_prot);

		return TRUE;
	}
	return FALSE;
}

BOOL PatchNop(HOOKER hooker, DWORD addr, DWORD size)
{
	return PatchSet(hooker, addr, 0x90, size);
}

BOOL PatchHex(HOOKER hooker, DWORD addr, CHAR* block)
{
	CHAR* ch = block;
	DWORD bt = 0;
	BOOL b = FALSE;
	DWORD size = 0;
	while (*ch)
	{
		if (*ch == ' ')
		{
			if (b)
			{
				bt = 0;
				++size;
				b = FALSE;
			}
		}
		else
		{
			if (bt > 0xF)
				return FALSE;

			bt <<= 4;
			if (*ch >= '0' && *ch <= '9')
				bt += *ch - '0';
			else if (*ch >= 'A' && *ch <= 'F')
				bt += *ch - 'A' + 10;
			else if (*ch >= 'a' && *ch <= 'f')
				bt += *ch - 'a' + 10;
			else
				return FALSE;

			b = TRUE;
		}

		++ch;
	}

	if (b)
		++size;
	else if (!size)
		return FALSE;

	DWORD address = addr + hooker->baseOffset;

	DWORD old_prot;
	if (VirtualProtect((VOID*)address, size, PAGE_EXECUTE_READWRITE, &old_prot))
	{
		BYTE* dst = (BYTE*)address;

		ch = block;
		bt = 0;
		b = FALSE;

		while (*ch)
		{
			if (*ch == ' ')
			{
				if (b)
				{
					*dst++ = LOBYTE(bt);
					bt = 0;
					b = FALSE;
				}
			}
			else
			{
				bt <<= 4;
				if (*ch >= '0' && *ch <= '9')
					bt += *ch - '0';
				else if (*ch >= 'A' && *ch <= 'F')
					bt += *ch - 'A' + 10;
				else
					bt += *ch - 'a' + 10;

				b = TRUE;
			}

			++ch;
		}

		if (b)
			*dst++ = LOBYTE(bt);

		VirtualProtect((VOID*)address, size, old_prot, &old_prot);

		return TRUE;
	}
	return FALSE;
}

BOOL PatchBlock(HOOKER hooker, DWORD addr, VOID* block, DWORD size)
{
	DWORD address = addr + hooker->baseOffset;

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
			MemoryCopy((VOID*)address, block, size);
			break;
		}

		VirtualProtect((VOID*)address, size, old_prot, &old_prot);

		return TRUE;
	}
	return FALSE;
}

BOOL PatchByte(HOOKER hooker, DWORD addr, BYTE value)
{
	return PatchBlock(hooker, addr, &value, sizeof(value));
}

BOOL PatchWord(HOOKER hooker, DWORD addr, WORD value)
{
	return PatchBlock(hooker, addr, &value, sizeof(value));
}

BOOL PatchDWord(HOOKER hooker, DWORD addr, DWORD value)
{
	return PatchBlock(hooker, addr, &value, sizeof(value));
}

DWORD PatchImport(HOOKER hooker, const CHAR* function, VOID* addr)
{
	PIMAGE_DATA_DIRECTORY dataDir = &hooker->headNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (dataDir->Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hooker->hModule + dataDir->VirtualAddress);
		for (DWORD idx = 0; imports->Name; ++idx, ++imports)
		{
			PIMAGE_THUNK_DATA addressThunk = (PIMAGE_THUNK_DATA)((DWORD)hooker->hModule + imports->FirstThunk);
			PIMAGE_THUNK_DATA nameThunk;
			if (imports->OriginalFirstThunk)
				nameThunk = (PIMAGE_THUNK_DATA)((DWORD)hooker->hModule + imports->OriginalFirstThunk);
			else if (MapFile(hooker))
			{
				PIMAGE_NT_HEADERS headNT = (PIMAGE_NT_HEADERS)((DWORD)hooker->mapAddress + ((PIMAGE_DOS_HEADER)hooker->mapAddress)->e_lfanew);
				PIMAGE_SECTION_HEADER sh = (PIMAGE_SECTION_HEADER)((DWORD)&headNT->OptionalHeader + headNT->FileHeader.SizeOfOptionalHeader);

				nameThunk = NULL;
				DWORD sCount = headNT->FileHeader.NumberOfSections;
				while (sCount--)
				{
					if (imports->FirstThunk >= sh->VirtualAddress && imports->FirstThunk < sh->VirtualAddress + sh->Misc.VirtualSize)
					{
						nameThunk = PIMAGE_THUNK_DATA((DWORD)hooker->mapAddress + sh->PointerToRawData + imports->FirstThunk - sh->VirtualAddress);
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
				PIMAGE_IMPORT_BY_NAME name = PIMAGE_IMPORT_BY_NAME((DWORD)hooker->hModule + nameThunk->u1.AddressOfData);

				WORD hint;
				if (ReadWord(hooker, (INT)name - hooker->baseOffset, &hint) && !StrCompare((CHAR*)name->Name, function))
				{
					DWORD res;
					if (ReadDWord(hooker, (INT)&addressThunk->u1.AddressOfData - hooker->baseOffset, &res))
					{
						PatchDWord(hooker, (INT)&addressThunk->u1.AddressOfData - hooker->baseOffset, (DWORD)addr);
						return res;
					}

					return NULL;
				}
			}
		}
	}

	return NULL;
}

DWORD PatchExport(HOOKER hooker, const CHAR* function, VOID* addr)
{
	DWORD func = (DWORD)GetProcAddress(hooker->hModule, function);
	if (func)
	{
		PIMAGE_DATA_DIRECTORY dataDir = &hooker->headNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (dataDir->Size)
		{
			PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hooker->hModule + dataDir->VirtualAddress);
			{
				DWORD* functions = (DWORD*)((DWORD)hooker->hModule + exports->AddressOfFunctions);

				for (DWORD i = 0; i < exports->NumberOfFunctions; ++i)
					if (func == (DWORD)hooker->hModule + functions[i])
						return PatchDWord(hooker, (DWORD)&functions[i] - hooker->baseOffset, (DWORD)addr - (DWORD)hooker->hModule);
			}
		}
	}

	return NULL;
}

DWORD PatchEntry(HOOKER hooker, VOID* entryPoint)
{
	DWORD res = (DWORD)this->hModule + this->headNT->OptionalHeader.AddressOfEntryPoint;
	if (PatchHook(hooker, res, entryPoint))
		return res + this->baseOffset;

	return NULL;
}
#pragma optimize("", on)
