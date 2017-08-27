/*
Read PE File format
*/

#include <stdio.h>
#include <windows.h>
#include <time.h>
#include <tchar.h>

void convertToHumanReadable(int time_stamp);

int main(int argc, char *argv[])
{
	int i = 0;
	LPVOID lpBase;
    HANDLE hMapObject,hFile;            //File Mapping Object
    IMAGE_DOS_HEADER* dosHeader;        //Pointer to DOS Header
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_FILE_HEADER fileHeader;
	IMAGE_OPTIONAL_HEADER opHeader;
	PIMAGE_SECTION_HEADER pSecHeader;
	IMAGE_SECTION_HEADER secHeader;
	IMAGE_EXPORT_DIRECTORY*export, *import;
	IMAGE_DATA_DIRECTORY*Export, *Import;

    char*fileName = "client.exe";

	hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("File could not be opened\n");
		return;
	};

	hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);

	dosHeader = (IMAGE_DOS_HEADER*)lpBase;

	printf("SIZE: %d\n", sizeof(IMAGE_DOS_HEADER));

	printf("Magic Number:\t\t%x - %c%c\n", dosHeader->e_magic, dosHeader->e_magic, dosHeader->e_magic >> 8);

	printf("e_lfanew:\t\t%08x\n", dosHeader->e_lfanew);

	ntHeader = (IMAGE_NT_HEADERS*)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	printf("PE Header:\t\t%c%c%d%d\n", ntHeader->Signature, ntHeader->Signature >> 8, ntHeader->Signature >> 18, ntHeader->Signature >> 24);

	fileHeader = ntHeader->FileHeader;

	printf("Number of Sections:\t%04d\n", fileHeader.NumberOfSections);
	
	printf("DLL or EXE: %p:", fileHeader.Characteristics);

	if (fileHeader.Characteristics & IMAGE_FILE_DLL)
	{
		printf("\tDLL\n");
	}
	else if (fileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
	{
		printf("\tEXE\n");
	}
	
	convertToHumanReadable((int)fileHeader.TimeDateStamp);

	opHeader = ntHeader->OptionalHeader;
	
	printf("Export Directory\n");
	Export = opHeader.DataDirectory;
	Import = &opHeader.DataDirectory[1];
	printf("\tAddress:\t0x%08x\n", Export->VirtualAddress);
	printf("\tSize:\t\t0x%08x\n", Export->Size);
	printf("Import Directory\n");
	printf("\tAddress:\t0x%08x\n", Import->VirtualAddress);
	printf("\tSize:\t\t0x%08x\n\n", Import->Size);
	
	printf("Entry Point:\t\t0x%08x\n\n", opHeader.AddressOfEntryPoint);
	
	for (pSecHeader = IMAGE_FIRST_SECTION(ntHeader), i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, pSecHeader)
	{
		printf("%s\n", pSecHeader[i].Name);
		printf("\tVirtualAddress: \t0x%08x\n", pSecHeader[i].VirtualAddress);
		printf("\tVirtualSize: \t\t0x%08x\n", pSecHeader[i].Misc.VirtualSize);
		printf("\tRawSize: \t\t0x%08x\n", pSecHeader[i].SizeOfRawData);
		printf("\tPointerToRaw: \t\t0x%08x\n\n", pSecHeader[i].PointerToRawData);
	}
	
}


void convertToHumanReadable(int epoch_time) {

	time_t c = epoch_time;

	printf("Time:\t\t\t%s",asctime(localtime(&c)));
}
