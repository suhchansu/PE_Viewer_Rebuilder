#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <stdio.h>

IMAGE_DOS_HEADER sDos;
IMAGE_NT_HEADERS sNt;
IMAGE_DATA_DIRECTORY sData;
IMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
IMAGE_IMPORT_BY_NAME imageImportByName;

//ImporAddressTable
PIMAGE_SECTION_HEADER sSection, pSectionHeader;
PIMAGE_DOS_HEADER pImageDosHeader;
PIMAGE_NT_HEADERS pImageNtHeader;
PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
PIMAGE_THUNK_DATA pImageTrunkData;
PIMAGE_IMPORT_BY_NAME pImportByName;

//ImportAddressTable
HANDLE hFile, hFileMap;
DWORD dwImportDirectoryVA, dwSectionCount, dwSection = 0;
DWORD file_size;
LPVOID fileImageBase;

//ExportAddressTable
PDWORD pAddress, pName, pOrdinal;
PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

FILE *fp;
unsigned long beforeAddressSize;
char peBuf[0x500];

DWORD RVAToRAW(DWORD rVA, PIMAGE_SECTION_HEADER pSecHeader, PIMAGE_NT_HEADERS pNtHeader)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER mPSecHeader;
	if (rVA == 0)
		return (rVA);

	mPSecHeader = pSecHeader;
	for (i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
		if (rVA >= mPSecHeader->VirtualAddress && rVA < mPSecHeader->VirtualAddress + mPSecHeader->Misc.VirtualSize)
			break;
		mPSecHeader++;
	}
	return (rVA - mPSecHeader->VirtualAddress + mPSecHeader->PointerToRawData);
}


class Init
{
private:

public:

	Init(char *filePath){
		InitHeaders(filePath);
		InitAddressTable(filePath);
	}

	// 헤더 연산을 위한 복사
	int InitHeaders(char *filePath) {
		if (fopen_s(&fp, filePath, "rb")) return EXIT_FAILURE;
		fread_s(peBuf, sizeof(peBuf), sizeof(peBuf), 1, fp);

		fclose(fp);
		return EXIT_SUCCESS;
	}

	// IAT, EAT 연산을 위한 복사
	void InitAddressTable(char *filePath)
	{
		hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
			printf("file open failed %s\n", filePath);

		file_size = GetFileSize(hFile, NULL);
		hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
		fileImageBase = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, file_size);

		pImageDosHeader = (PIMAGE_DOS_HEADER)fileImageBase;
		pImageNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew);

		pSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeader);	// pSectionHeader의 offset 구하기
	}
};

class DoInterface {
private:

public:
	virtual void Set() = 0;
	virtual void Show() = 0;
};

DoInterface *list[5];

class Header_Dos : public DoInterface {
private:

public:
	void Set();
	void Show();
};

void Header_Dos::Set() {
	memcpy_s(&sDos, sizeof(IMAGE_DOS_HEADER), peBuf, sizeof(IMAGE_DOS_HEADER));
}

void Header_Dos:: Show() 
{
	printf("DOS_HEADER\n");
	printf("-------------------------------------------------------------------------------\n");
	printf("%08X\t%08X\t\tSignature\n", offsetof(IMAGE_DOS_HEADER, e_magic), sDos.e_magic);
	printf("%08X\t%08X\t\tBytes on last Page of File\n", offsetof(IMAGE_DOS_HEADER, e_cblp), sDos.e_cblp);
	printf("%08X\t%08X\t\tPages in File\n", offsetof(IMAGE_DOS_HEADER, e_cp), sDos.e_cp);
	printf("%08X\t%08X\t\tRelocations\n", offsetof(IMAGE_DOS_HEADER, e_crlc), sDos.e_crlc);
	printf("%08X\t%08X\t\tSize of Header in Paragraphs\n", offsetof(IMAGE_DOS_HEADER, e_cparhdr), sDos.e_cparhdr);
	printf("%08X\t%08X\t\tMinimum Extra Paragraphs\n", offsetof(IMAGE_DOS_HEADER, e_minalloc), sDos.e_minalloc);
	printf("%08X\t%08X\t\tMaximum Extra Paragraphs\n", offsetof(IMAGE_DOS_HEADER, e_maxalloc), sDos.e_maxalloc);
	printf("%08X\t%08X\t\tInitial (relative) SS\n", offsetof(IMAGE_DOS_HEADER, e_ss), sDos.e_ss);
	printf("%08X\t%08X\t\tInitial SP\n", offsetof(IMAGE_DOS_HEADER, e_sp), sDos.e_sp);
	printf("%08X\t%08X\t\tChecksum\n", offsetof(IMAGE_DOS_HEADER, e_csum), sDos.e_csum);
	printf("%08X\t%08X\t\tInitial IP\n", offsetof(IMAGE_DOS_HEADER, e_ip), sDos.e_ip);
	printf("%08X\t%08X\t\tInitial (relative) CS value\n", offsetof(IMAGE_DOS_HEADER, e_cs), sDos.e_cs);
	printf("%08X\t%08X\t\tFile address of relocation Table\n", offsetof(IMAGE_DOS_HEADER, e_lfarlc), sDos.e_lfarlc);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_ovno), sDos.e_ovno);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res[0]), sDos.e_res[0]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res[1]), sDos.e_res[1]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res[2]), sDos.e_res[2]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res[3]), sDos.e_res[3]);
	printf("%08X\t%08X\t\tOEM identifier (for e_oeminfo)\n", offsetof(IMAGE_DOS_HEADER, e_oemid), sDos.e_oemid);
	printf("%08X\t%08X\t\tOEM information;e_oemid specific\n", offsetof(IMAGE_DOS_HEADER, e_oeminfo), sDos.e_oeminfo);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[0]), sDos.e_res2[0]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[1]), sDos.e_res2[1]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[2]), sDos.e_res2[2]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[3]), sDos.e_res2[3]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[4]), sDos.e_res2[4]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[5]), sDos.e_res2[5]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[6]), sDos.e_res2[6]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[7]), sDos.e_res2[7]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[8]), sDos.e_res2[8]);
	printf("%08X\t%08X\t\tOverlay number\n", offsetof(IMAGE_DOS_HEADER, e_res2[9]), sDos.e_res2[9]);
	printf("%08X\t%08X\t\tOffset to NT header\n\n", offsetof(IMAGE_DOS_HEADER, e_lfanew), sDos.e_lfanew);
}


class Header_Nt : public DoInterface {
private:

public:
	void Set() {
		memcpy_s(&sNt, sizeof(IMAGE_NT_HEADERS), (peBuf + sDos.e_lfanew), sizeof(IMAGE_NT_HEADERS));
	}

	void Show() {
		printf("NT_HEADER\n");
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tNT signature\n\n", offsetof(IMAGE_NT_HEADERS, Signature) + sDos.e_lfanew, sNt.Signature);

		beforeAddressSize = sDos.e_lfanew + sizeof(DWORD);

		printf("NT_HEADER__IMAGE_FILE_HEADER\n");
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%04X\t\t\tMachine\n", offsetof(IMAGE_FILE_HEADER, Machine) + beforeAddressSize, sNt.FileHeader.Machine);
		printf("%08X\t%04X\t\t\tNumber of Sections\n", offsetof(IMAGE_FILE_HEADER, NumberOfSections) + beforeAddressSize, sNt.FileHeader.NumberOfSections);
		printf("%08X\t%08X\t\tTime Date Stamp\n", offsetof(IMAGE_FILE_HEADER, TimeDateStamp) + beforeAddressSize, sNt.FileHeader.TimeDateStamp);
		printf("%08X\t%08X\t\tPointer to Symbol Table\n", offsetof(IMAGE_FILE_HEADER, PointerToSymbolTable) + beforeAddressSize, sNt.FileHeader.PointerToSymbolTable);
		printf("%08X\t%08X\t\tNumber of Symbols\n", offsetof(IMAGE_FILE_HEADER, NumberOfSymbols) + beforeAddressSize, sNt.FileHeader.NumberOfSymbols);
		printf("%08X\t%04X\t\t\tSize of Optional Header\n", offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader) + beforeAddressSize, sNt.FileHeader.SizeOfOptionalHeader);
		printf("%08X\t%04X\t\t\tCharacteristics\n\n", offsetof(IMAGE_FILE_HEADER, Characteristics) + beforeAddressSize, sNt.FileHeader.Characteristics);

		beforeAddressSize += sizeof(IMAGE_FILE_HEADER);

		printf("NT_HEADER__IMAGE_OPTIONAL_HEADER\n");
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%04X\t\t\tMagic\n", offsetof(IMAGE_OPTIONAL_HEADER, Magic) + beforeAddressSize, sNt.OptionalHeader.Magic);
		printf("%08X\t%02X\t\t\tMajor Linker Version\n", offsetof(IMAGE_OPTIONAL_HEADER, MajorLinkerVersion) + beforeAddressSize, sNt.OptionalHeader.MajorLinkerVersion);
		printf("%08X\t%02X\t\t\tMinor Linker Version\n", offsetof(IMAGE_OPTIONAL_HEADER, MinorLinkerVersion) + beforeAddressSize, sNt.OptionalHeader.MinorLinkerVersion);
		printf("%08X\t%08X\t\tSize of Code\n", offsetof(IMAGE_OPTIONAL_HEADER, SizeOfCode) + beforeAddressSize, sNt.OptionalHeader.SizeOfCode);
		printf("%08X\t%08X\t\tSize of Initialized Data\n", offsetof(IMAGE_OPTIONAL_HEADER, SizeOfInitializedData) + beforeAddressSize, sNt.OptionalHeader.SizeOfInitializedData);
		printf("%08X\t%08X\t\tSize of Uninitialized Data\n", offsetof(IMAGE_OPTIONAL_HEADER, SizeOfUninitializedData) + beforeAddressSize, sNt.OptionalHeader.SizeOfUninitializedData);
		printf("%08X\t%08X\t\tAddress of Entry Point\n", offsetof(IMAGE_OPTIONAL_HEADER, AddressOfEntryPoint) + beforeAddressSize, sNt.OptionalHeader.AddressOfEntryPoint);
		printf("%08X\t%08X\t\tBase of Code\n", offsetof(IMAGE_OPTIONAL_HEADER, BaseOfCode) + beforeAddressSize, sNt.OptionalHeader.BaseOfCode);
		printf("%08X\t%08X\t\tBase of Data\n", offsetof(IMAGE_OPTIONAL_HEADER, BaseOfData) + beforeAddressSize, sNt.OptionalHeader.BaseOfData);
		printf("%08X\t%08X\t\tImage Base\n", offsetof(IMAGE_OPTIONAL_HEADER, ImageBase) + beforeAddressSize, sNt.OptionalHeader.ImageBase);
		printf("%08X\t%08X\t\tSection Alignment\n", offsetof(IMAGE_OPTIONAL_HEADER, SectionAlignment) + beforeAddressSize, sNt.OptionalHeader.SectionAlignment);
		printf("%08X\t%08X\t\tFile Alignment\n", offsetof(IMAGE_OPTIONAL_HEADER, FileAlignment) + beforeAddressSize, sNt.OptionalHeader.FileAlignment);
		printf("%08X\t%04X\t\t\tMajor O/S Version\n", offsetof(IMAGE_OPTIONAL_HEADER, MajorOperatingSystemVersion) + beforeAddressSize, sNt.OptionalHeader.MajorOperatingSystemVersion);
		printf("%08X\t%04X\t\t\tMinor O/S Version\n", offsetof(IMAGE_OPTIONAL_HEADER, MinorOperatingSystemVersion) + beforeAddressSize, sNt.OptionalHeader.MinorOperatingSystemVersion);
		printf("%08X\t%04X\t\t\tMajor Image Version\n", offsetof(IMAGE_OPTIONAL_HEADER, MajorImageVersion) + beforeAddressSize, sNt.OptionalHeader.MajorImageVersion);
		printf("%08X\t%04X\t\t\tMinor Image Version\n", offsetof(IMAGE_OPTIONAL_HEADER, MinorImageVersion) + beforeAddressSize, sNt.OptionalHeader.MinorImageVersion);
		printf("%08X\t%04X\t\t\tMajor Subsystem Version\n", offsetof(IMAGE_OPTIONAL_HEADER, MajorSubsystemVersion) + beforeAddressSize, sNt.OptionalHeader.MajorSubsystemVersion);
		printf("%08X\t%04X\t\t\tMinor Subsystem Version\n", offsetof(IMAGE_OPTIONAL_HEADER, MinorImageVersion) + beforeAddressSize, sNt.OptionalHeader.MinorSubsystemVersion);
		printf("%08X\t%08X\t\tWin32 Version Value\n", offsetof(IMAGE_OPTIONAL_HEADER, Win32VersionValue) + beforeAddressSize, sNt.OptionalHeader.Win32VersionValue);
		printf("%08X\t%08X\t\tSize of Image\n", offsetof(IMAGE_OPTIONAL_HEADER, SizeOfImage) + beforeAddressSize, sNt.OptionalHeader.SizeOfImage);
		printf("%08X\t%08X\t\tSize of Headers\n", offsetof(IMAGE_OPTIONAL_HEADER, SizeOfHeaders) + beforeAddressSize, sNt.OptionalHeader.SizeOfHeaders);
		printf("%08X\t%08X\t\tChecksum\n", offsetof(IMAGE_OPTIONAL_HEADER, CheckSum) + beforeAddressSize, sNt.OptionalHeader.CheckSum);
		printf("%08X\t%04X\t\t\tSubsystem\n", offsetof(IMAGE_OPTIONAL_HEADER, Subsystem) + beforeAddressSize, sNt.OptionalHeader.Subsystem);
		printf("%08X\t%04X\t\t\tDLL Characteristics\n", offsetof(IMAGE_OPTIONAL_HEADER, DllCharacteristics) + beforeAddressSize, sNt.OptionalHeader.DllCharacteristics);
		printf("%08X\t%08X\t\tSize of Stack Reserve\n", offsetof(IMAGE_OPTIONAL_HEADER, SizeOfStackReserve) + beforeAddressSize, sNt.OptionalHeader.SizeOfStackReserve);
		printf("%08X\t%08X\t\tSize of Stack Commit\n", offsetof(IMAGE_OPTIONAL_HEADER, SizeOfStackCommit) + beforeAddressSize, sNt.OptionalHeader.SizeOfStackCommit);
		printf("%08X\t%08X\t\tSize of Heap Reserve\n", offsetof(IMAGE_OPTIONAL_HEADER, SizeOfHeapReserve) + beforeAddressSize, sNt.OptionalHeader.SizeOfHeapReserve);
		printf("%08X\t%08X\t\tSize of Heap Commit\n", offsetof(IMAGE_OPTIONAL_HEADER, SizeOfHeapCommit) + beforeAddressSize, sNt.OptionalHeader.SizeOfHeapCommit);
		printf("%08X\t%08X\t\tLoader Flags\n", offsetof(IMAGE_OPTIONAL_HEADER, LoaderFlags) + beforeAddressSize, sNt.OptionalHeader.LoaderFlags);
		printf("%08X\t%08X\t\tNumber of Data Directories\n\n", offsetof(IMAGE_OPTIONAL_HEADER, NumberOfRvaAndSizes) + beforeAddressSize, sNt.OptionalHeader.NumberOfRvaAndSizes);

		printf("NT_HEADER__Directories\n");
		printf("-------------------------------------------------------------------------------\n");
		// Export Table
		printf("%08X\t%08X\t\tRVA (Export Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[0].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[0].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Export Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[0].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[0].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Import Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[1].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[1].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Import Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[1].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[1].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Resource Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[2].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[2].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Resource Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[2].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[2].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Exception Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[3].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[3].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Exception Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[3].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[3].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Certificate Talbe)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[4].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[4].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Certificate Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[4].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[4].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Base Relocation Talbe)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[5].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[5].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Base Relocation Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[5].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[5].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Debug Directory)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[6].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[6].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Debug Directory)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[6].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[6].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Architecture Specific Data)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[7].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[7].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Architecture Specific Data)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[7].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[7].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Global Pointer Register)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[8].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[8].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Global Pointer Register)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[8].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[8].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (TLS Talbe)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[9].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[9].VirtualAddress);
		printf("%08X\t%08X\t\tSize (TLS Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[9].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[9].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Load Configuration Talbe)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[10].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[10].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Load Configuration Talbe)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[10].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[10].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Bound Import Talbe)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[11].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[11].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Bound Import Talbe)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[11].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[11].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Import Address Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[12].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[12].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Import Address Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[12].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[12].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (Delay Import Talbe)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[13].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[13].VirtualAddress);
		printf("%08X\t%08X\t\tSize (Delay Import Table)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[13].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[13].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA (CLI Header)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[14].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[14].VirtualAddress);
		printf("%08X\t%08X\t\tSize (CLI Header)\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[14].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[14].Size);
		printf("-------------------------------------------------------------------------------\n");
		printf("%08X\t%08X\t\tRVA\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[15].VirtualAddress) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[15].VirtualAddress);
		printf("%08X\t%08X\t\tSize\n\n\n", offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory[15].Size) + beforeAddressSize, sNt.OptionalHeader.DataDirectory[15].Size);

	}
};

class Header_Sections : public DoInterface {
private:
	int nCount;
public:
	void Set() {
		//Section의 갯수 파악 밑 복사
		sSection = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * sNt.FileHeader.NumberOfSections);
		for (nCount = 0; nCount < sNt.FileHeader.NumberOfSections; nCount++)
			memcpy_s(&sSection[nCount], sizeof(IMAGE_SECTION_HEADER), (peBuf + (sDos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) + (sizeof(IMAGE_SECTION_HEADER) * nCount))), sizeof(IMAGE_SECTION_HEADER));
	}

	void Show() {
		beforeAddressSize += sizeof(IMAGE_OPTIONAL_HEADER) + sNt.OptionalHeader.DataDirectory[15].Size;

		for (nCount = 0; nCount < sNt.FileHeader.NumberOfSections; nCount++)
		{
			printf("SECTION_HEADER\n");
			printf("-------------------------------------------------------------------------------\n");
			printf("%08X\t%s\t\t\tName\n", offsetof(IMAGE_SECTION_HEADER, Name) + beforeAddressSize, sSection[nCount].Name);
			printf("%08X\t%08X\t\tVirtual Size\n", offsetof(IMAGE_SECTION_HEADER, Misc.VirtualSize) + beforeAddressSize, sSection[nCount].Misc.VirtualSize);
			printf("%08X\t%08X\t\tRVA ( Virtual Address )\n", offsetof(IMAGE_SECTION_HEADER, VirtualAddress) + beforeAddressSize, sSection[nCount].VirtualAddress);
			printf("%08X\t%08X\t\tSize of Raw Data\n", offsetof(IMAGE_SECTION_HEADER, SizeOfRawData) + beforeAddressSize, sSection[nCount].SizeOfRawData);
			printf("%08X\t%08X\t\tPointer to Raw Data\n", offsetof(IMAGE_SECTION_HEADER, PointerToRawData) + beforeAddressSize, sSection[nCount].PointerToRawData);
			printf("%08X\t%08X\t\tPointer to Relocations\n", offsetof(IMAGE_SECTION_HEADER, PointerToRelocations) + beforeAddressSize, sSection[nCount].PointerToRelocations);
			printf("%08X\t%08X\t\tPointer to Line Numbers\n", offsetof(IMAGE_SECTION_HEADER, PointerToLinenumbers) + beforeAddressSize, sSection[nCount].PointerToLinenumbers);
			printf("%08X\t%04X\t\t\tNumber of Relocations\n", offsetof(IMAGE_SECTION_HEADER, NumberOfRelocations) + beforeAddressSize, sSection[nCount].NumberOfRelocations);
			printf("%08X\t%04X\t\t\tNumber of Line Numbers\n", offsetof(IMAGE_SECTION_HEADER, NumberOfLinenumbers) + beforeAddressSize, sSection[nCount].NumberOfLinenumbers);
			printf("%08X\t%08X\t\tCharaterisics\n\n\n", offsetof(IMAGE_SECTION_HEADER, Characteristics) + beforeAddressSize, sSection[nCount].Characteristics);
		}
	}
};

class  Body_IAT : public DoInterface {
private:
public:
	void Set() {
		dwSectionCount = pImageNtHeader->FileHeader.NumberOfSections;	// section의 갯수
		dwImportDirectoryVA = pImageNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress; // 실제 IMAGE_IMPORT_DESCRIPTOR 구조체 배열의 시작 주소 ( RVA ) 

		for (; dwSection < dwSectionCount && pSectionHeader->VirtualAddress <= dwImportDirectoryVA; pSectionHeader++, dwSection++);	// section의 위치 찾기
		pSectionHeader--;

		pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)fileImageBase + RVAToRAW(pImageNtHeader-> \
			OptionalHeader.DataDirectory[1].VirtualAddress, pSectionHeader, pImageNtHeader));

		beforeAddressSize += sizeof(PIMAGE_IMPORT_DESCRIPTOR) + sSection->Characteristics;

		printf("Import Address Table\n");
		printf("-------------------------------------------------------------------------------\n");
		// IMPORT Directory Table 과 IMPORT_DESCRIPTOR 는 같다.
		while (pImageImportDescriptor->Name) {
			if (pImageImportDescriptor->Name != NULL) {
				// pImageImportDescriptor->Name 은 RVA 값이다. 이것은 DLL 파일명이 있는 위치의 RVA를 가지고 있다. 참조하기위해서는 이미지베이스주소(fileImageBase) 를 더해야 유효한 메모리상의 주소가 된다.

				printf("DLL: %s\n", (PCHAR)((DWORD_PTR)fileImageBase + RVAToRAW(pImageImportDescriptor->Name, pSectionHeader, pImageNtHeader)));

				// pImageTrunkData = IAT 안의 해당 DLL 첫 API 시작엔트리, pImageImportDescriptor->OriginalFirstThunk 의 DWORD 크기의 배열을 읽는다 ( 함수로 점프하기 위한 VA가 있다 )
				pImageTrunkData = (PIMAGE_THUNK_DATA)((DWORD)fileImageBase + RVAToRAW(pImageImportDescriptor->OriginalFirstThunk, pSectionHeader, pImageNtHeader));

				for (; pImageTrunkData->u1.AddressOfData != 0; pImageTrunkData++) {
					if (pImageTrunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						printf("%08X\t%04u\n", (PVOID)((LPBYTE)pImageTrunkData->u1.Ordinal), \
							IMAGE_ORDINAL(pImageTrunkData->u1.Ordinal));
					}
					else {
						printf("%08X\t%s\n", (PVOID)((LPBYTE)pImageTrunkData->u1.AddressOfData), \
							(PCHAR)((DWORD)fileImageBase + 2 + RVAToRAW(pImageTrunkData->u1.AddressOfData, pSectionHeader, pImageNtHeader)));
					}
				}
				printf("-------------------------------------------------------------------------------\n");
			}
			pImageImportDescriptor++;
		}
	}
	void Show() { printf("\n"); }
};

class Body_EAT : public DoInterface {
private:
public:
	void Set() {
		if (sNt.OptionalHeader.DataDirectory[0].VirtualAddress == 0) exit(0);

		// EAT 시작위치 파악
		pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)fileImageBase + RVAToRAW(pImageNtHeader-> \
			OptionalHeader.DataDirectory[0].VirtualAddress, pSectionHeader, pImageNtHeader));

		printf("\n\n\nExport Address Table\n");
		printf("DLL name: %s\n", (PCHAR)((DWORD_PTR)fileImageBase + RVAToRAW(pImageExportDirectory->Name, pSectionHeader, pImageNtHeader)));
		printf("Number of Fucntions : %d개\n", pImageExportDirectory->NumberOfFunctions);
		printf("-------------------------------------------------------------------------------\n");
		pAddress = (PDWORD)((DWORD)fileImageBase + pImageExportDirectory->AddressOfFunctions);
		pName = (PDWORD)((DWORD)fileImageBase + pImageExportDirectory->AddressOfNames);
		pOrdinal = (PDWORD)((DWORD)fileImageBase + pImageExportDirectory->AddressOfNameOrdinals);

		for (int i = 0; i < pImageExportDirectory->NumberOfFunctions; i++) {
			printf("%08X\t%s\n", (PVOID)((LPBYTE)pAddress[i]), \
				(PCHAR)((DWORD)fileImageBase + RVAToRAW(pName[i], pSectionHeader, pImageNtHeader)));
		}

		// IAT, EAT를 위해 할당한 핸들과 맵핑 해제
		UnmapViewOfFile(fileImageBase);
		CloseHandle(hFile);
	}
	void Show() { printf("\n"); }

};

// interface 초기화 작업
class InterfaceInit {
public :
	InterfaceInit() {
		Iinit();
	}
	void Iinit() {
		DoInterface *dos = new Header_Dos;
		DoInterface *nt = new Header_Nt;
		DoInterface *section = new Header_Sections;
		DoInterface *iat = new Body_IAT;
		DoInterface *eat = new Body_EAT;

		list[0] = dos, list[1] = nt, list[2] = section, list[3] = iat, list[4] = eat;
	}
};
