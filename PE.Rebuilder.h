#include <stdio.h>
#include <Windows.h>

IMAGE_DOS_HEADER sDos;
IMAGE_NT_HEADERS sNt;
PIMAGE_SECTION_HEADER pSection;

PIMAGE_DATA_DIRECTORY reloc_entry;

PIMAGE_BASE_RELOCATION base_reloc;
PIMAGE_BASE_RELOCATION pRelocation;

FILE *fp, *fout;
char peBuf[0x500];
char tempBuf[300000];

class Realloc
{
	Realloc() {
		reloc_entry = &sNt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		base_reloc = (PIMAGE_BASE_RELOCATION)((char *)pRelocation + reloc_entry->VirtualAddress);
		fix_relocations(base_reloc, reloc_entry->Size, (DWORD)pRelocation, sNt.OptionalHeader.ImageBase);
	}
	void fix_relocations(IMAGE_BASE_RELOCATION *base_reloc, DWORD dir_size, DWORD new_imgbase, DWORD old_imgbase)
	{
		//	fix_relocations(pRelocation, reloc_entry->Size, (DWORD)peBuf, sNt.OptionalHeader.ImageBase);
		IMAGE_BASE_RELOCATION *cur_reloc = base_reloc, *reloc_end;
		DWORD delta = new_imgbase - old_imgbase;	// new_imgbase : 실제 로드한 주소, old_imgbase : 프로그램의 기준주소
		reloc_end = (IMAGE_BASE_RELOCATION *)((char *)base_reloc + dir_size);

		while (cur_reloc < reloc_end && cur_reloc->VirtualAddress) {
			// typeoffset 갯수
			int count = (cur_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			// typeoffset의 index
			WORD *cur_entry = (WORD *)(cur_reloc + 1);
			void *page_va = (void *)((char *)new_imgbase + cur_reloc->VirtualAddress);

			while (count--) {
				// x86 체크 -> reloc 실행
				if (*cur_entry >> 12 == IMAGE_REL_BASED_HIGHLOW) {
					*(DWORD *)((char *)page_va + (*cur_entry & 0x0fff)) += delta;
				}
				cur_entry++;
			}
			cur_reloc = (IMAGE_BASE_RELOCATION *)((char *)cur_reloc + cur_reloc->SizeOfBlock);
		}
	}
};

class Init
{
public:
	Init(char *FilePath) {
		if (fopen_s(&fp, FilePath, "rb")) exit(0);
		fread_s(peBuf, sizeof(peBuf), sizeof(peBuf), 1, fp);
		fopen_s(&fout, "result.bin", "wb");
	}
};


class Rebuilder
{
public:
	Rebuilder() {
		int nCount;

		//Dos, NT Structure에 fopen한 데이터 저장
		memcpy_s(&sDos, sizeof(IMAGE_DOS_HEADER), peBuf, sizeof(IMAGE_DOS_HEADER));
		memcpy_s(&sNt, sizeof(IMAGE_NT_HEADERS), (peBuf + sDos.e_lfanew), sizeof(IMAGE_NT_HEADERS));

		//Section전 까지 짤라 붙이기 
		fseek(fp, 0, SEEK_SET);
		fread(peBuf, sNt.OptionalHeader.SizeOfHeaders, 1, fp);
		fwrite(peBuf, sNt.OptionalHeader.SizeOfHeaders, 1, fout);

		pSection = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * sNt.FileHeader.NumberOfSections);
		for (nCount = 0; nCount < sNt.FileHeader.NumberOfSections; nCount++)
			memcpy_s(&pSection[nCount], sizeof(IMAGE_SECTION_HEADER), (peBuf + (sDos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) \
				+ sizeof(IMAGE_OPTIONAL_HEADER32) + (sizeof(IMAGE_SECTION_HEADER) * nCount))), sizeof(IMAGE_SECTION_HEADER));

		//Section별로 짤라 붙이기
		for (nCount = 0; nCount < sNt.FileHeader.NumberOfSections; nCount++) {
			fseek(fp, pSection[nCount].VirtualAddress, SEEK_SET);
			fread(tempBuf, pSection[nCount].SizeOfRawData, 1, fp);
			fwrite(tempBuf, pSection[nCount].SizeOfRawData, 1, fout);
		}
	}

};

