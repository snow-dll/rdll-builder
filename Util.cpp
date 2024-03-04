#include "Util.h"

DWORD ExtractLdrAddress
(
	_In_	LPCSTR	lpModPath
)
{
	HMODULE					hMod;
	PIMAGE_DOS_HEADER		pDos;
	PIMAGE_NT_HEADERS		pNt;
	PIMAGE_EXPORT_DIRECTORY pExport;
	PDWORD					AddressOfFunctions;
	PDWORD					AddressOfNames;
	PWORD					AddressOfOrdinals;
	DWORD					fnAddr = NULL;

	hMod = LoadLibraryA(lpModPath);
	if (hMod == NULL)
		return NULL;

	pDos = (PIMAGE_DOS_HEADER)hMod;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	pNt = (PIMAGE_NT_HEADERS)((LPBYTE)hMod + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		return NULL;

	pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hMod + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);

	AddressOfFunctions	= (PDWORD)	((LPBYTE)hMod + pExport->AddressOfFunctions);
	AddressOfNames		= (PDWORD)	((LPBYTE)hMod + pExport->AddressOfNames);
	AddressOfOrdinals	= (PWORD)	((LPBYTE)hMod + pExport->AddressOfNameOrdinals);

	for (INT i = 0; i < pExport->NumberOfFunctions; i++)
	{
		if (!strcmp("ReflectiveLoader", (char*)hMod + AddressOfNames[i]))
		{
			fnAddr = (DWORD)((LPBYTE)hMod + AddressOfFunctions[AddressOfOrdinals[i]]);
			fnAddr = fnAddr - pNt->OptionalHeader.ImageBase;
		}
	}

	if (fnAddr == NULL)
		return NULL;

	PIMAGE_SECTION_HEADER pSect = IMAGE_FIRST_SECTION(pNt);
	DWORD delta = pSect->VirtualAddress - pSect->PointerToRawData;

	FreeLibrary(hMod);

	return fnAddr - delta;
}