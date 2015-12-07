#include <windows.h>
#include <stdio.h>

#include "decrypter.h"

#define unsigned int u_int;
// макрос для создания указателя со смещением
#define MAKE_PTR(cast, base, offset) (cast)((DWORD_PTR)(base) + (DWORD_PTR)(offset))
// макрос для выравнивания секций
#define ALIGN(X,Y) ((X+(Y-1))&(~(Y-1)))
#define XOR(X,Y) ((~(X)&(Y))|((X)&(~(Y))))


// функция генерации ключей
inline DWORD generator(DWORD size)
{
	return (size >> 1) & size;
}

int main(int argc, char *argv[])
{	
	if (argc == 1){
		printf("%s\n", "Usage: Crypter.exe <file for crypt>");
	}
	else {
		if (!strcmp(argv[1], "help")) {
			printf("%s\n", "Usage: Crypter.exe <file for crypt>");
		}
		// открытие файла
		HANDLE h_file = CreateFile(argv[1], GENERIC_READ,
			FILE_SHARE_READ, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);

		// проверка открытия файла
		if (h_file == INVALID_HANDLE_VALUE) return 0;
		DWORD image_size = GetFileSize(h_file, 0);
		LPBYTE image = new BYTE[image_size];

		// память для образа программы
		LPBYTE crypted_image = new BYTE[image_size];


		DWORD readed;
		ReadFile(h_file, image, image_size, &readed, 0);
		CloseHandle(h_file);
		crypted_image = image;

		DWORD crypted_size;
		crypted_size = image_size;

		// выделение памяти под массив для лоадера + образа программы + запас на выравнивание в памяти
		PBYTE loader_copy = new BYTE[decrypter_size + crypted_size + 0x1000];
		memcpy(loader_copy, (LPBYTE)&decrypter, decrypter_size);


		HMODULE _hmodule = (HMODULE)loader_copy;

		// поиск заголовком PE фалйа
		PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)_hmodule;
		PIMAGE_NT_HEADERS NT_headers = MAKE_PTR(PIMAGE_NT_HEADERS, _hmodule, dos_header->e_lfanew);
		PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(NT_headers);

		// ксор образа ( типо шифроване )
		for (u_int i = 0; i < image_size; i++)
		{
			image[i] = XOR(image[i], generator(i));
		}

		// поиск меток в массиве лоадера и их инициализация
		for (u_int i = 0; i < decrypter_size; i++)
			if (*(DWORD*)(&loader_copy[i]) == 0xBEEFCACE){
				*(DWORD*)(&loader_copy[i]) = crypted_size;
			}

			else if (*(DWORD*)(&loader_copy[i]) == 0xDEADBEEF)
				*(DWORD*)(&loader_copy[i]) = NT_headers->OptionalHeader.ImageBase +
				sections[1].VirtualAddress +
				sections[1].Misc.VirtualSize;

		// перенос зашифрованого образа в последнюю секцию лоадера
		memcpy(&loader_copy[sections[1].PointerToRawData + sections[1].Misc.VirtualSize],
			crypted_image, crypted_size);

		// замена старого размера секции новым, для секции в которую положен образ
		sections[1].SizeOfRawData = ALIGN(sections[1].Misc.VirtualSize + crypted_size,
			NT_headers->OptionalHeader.FileAlignment);

		// исправление размера секции в памяти
		sections[1].Misc.VirtualSize += crypted_size;

		// исправление общего размера образа в памяти
		NT_headers->OptionalHeader.SizeOfImage = ALIGN(sections[1].Misc.VirtualSize + sections[1].VirtualAddress,
			NT_headers->OptionalHeader.SectionAlignment);

		DWORD new_file_size = sections[1].SizeOfRawData + sections[1].PointerToRawData;

		h_file = CreateFile(argv[1], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (h_file != INVALID_HANDLE_VALUE)
		{
			DWORD written;
			WriteFile(h_file, loader_copy, new_file_size, &written, NULL);
			CloseHandle(h_file);
		}
	}
	return 0;
}
