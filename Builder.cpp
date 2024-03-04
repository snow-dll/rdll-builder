#include "Common.h"
#include "Util.h"

unsigned char loaderStub[] =
"\x4D\x5A\x41\x52\x55\x48\x89\xE5\x48\x81\xEC\x20\x00\x00\x00\x48"
"\x8D\x1D\xEA\xFF\xFF\xFF\x48\x89\xDF\x48\x81\xC3\xEE\xEE\xEE\xEE"
"\xFF\xD3\x41\xB8\xF0\xB5\xA2\x56\x68\x04\x00\x00\x00\x5A\x48\x89"
"\xF9\xFF\xD0";

int main(int argc, char* argv[])
{

	if (argc < 4)
	{
		printf("Usage: Builder.exe <source> <target>\n");
	}

	DWORD dwLdrAddress;
	LPCSTR lpModPath = argv[1];

	dwLdrAddress = ExtractLdrAddress(lpModPath);
	if (dwLdrAddress == NULL)
	{
		SetLastError(ERROR_INVALID_FUNCTION);
		return -1;
	}

	unsigned char b1, b2, b3, b4;
	b1 = (dwLdrAddress & 0x000000ff) >> 0;
	b2 = (dwLdrAddress & 0x0000ff00) >> 8;
	b3 = (dwLdrAddress & 0x00ff0000) >> 16;
	b4 = (dwLdrAddress & 0xff000000) >> 24;
	
	for (int i = 0; i < sizeof(loaderStub); i++)
	{
		if (loaderStub[i] == 0xEE)
		{
			loaderStub[i + 0] = b1;
			loaderStub[i + 1] = b2;
			loaderStub[i + 2] = b3;
			loaderStub[i + 3] = b4;
		}
	}

	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) return -1;
	DWORD dwSize = GetFileSize(hFile, NULL);
	HANDLE hData = HeapAlloc(GetProcessHeap(), 0, dwSize);
	if (hData == NULL)
		return -7;
	if (!ReadFile(hFile, hData, dwSize, nullptr, nullptr))
		return -8;

	if (dwSize < sizeof(loaderStub))
		return -9;

	memcpy(hData, loaderStub, sizeof(loaderStub));
	CloseHandle(hFile);

	HANDLE hFile2 = CreateFileA(argv[2], GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile2 == INVALID_HANDLE_VALUE) return -1;
	WriteFile(hFile2, hData, dwSize, nullptr, NULL);
	CloseHandle(hFile2);

	return 0;
}