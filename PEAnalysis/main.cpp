#include <iostream>
#include <vector>
#include <string>
#include <tuple>
#include <Windows.h>
#include "pe.hpp"

using namespace std;


int main() {
	PEHelper pe_info;
	//pe_info.ReadPEHeaderByName("C:/Users/qiufeng/Desktop/hello_world.exe");
	pe_info.ReadPEHeaderByName("C:/Users/qiufeng/Desktop/user32.dll");
	//pe_info.ReadPEHeaderByName("C:/Users/qiufeng/Desktop/user64.dll");
	cout << hex;
	cout << pe_info.GetImageBase() << endl;
	cout << pe_info.RVAToFOA(0x12314) << endl;

	vector<string> names = pe_info.GetSectionNames();
	cout << "节名：" << endl;
	for (auto it = names.begin(); it != names.end(); it++) {
		cout << (*it) << endl;
	}

	vector<IMAGE_IMPORT_DESCRIPTOR> import_descriptor = pe_info.GetImageImportDescriptors();
	vector<IMAGE_THUNK_DATA32> thunk_data32 = pe_info.GetImageThunkData32(import_descriptor[0]);
	vector<string> dll_names = pe_info.GetImportDLLNames();
	cout << "引入的dll名：" << endl;
	for (auto it = dll_names.begin(); it != dll_names.end(); it++) {
		cout << (*it) << endl;
	}

	vector<tuple<WORD, string>> function_names = pe_info.GetImportFunctionNames(import_descriptor[1]);
	IMAGE_EXPORT_DIRECTORY edt = pe_info.GetExportDirectory();
	DWORD message_rva = pe_info.GetExportFunctionRVA("MessageBoxA");

	cout << "是否开启 ALSR: " << pe_info.HasASLR() << endl;
	pe_info.CloseASLR();
	cout << "是否开启 ALSR: " << pe_info.HasASLR() << endl;
	pe_info.OpenASLR();
	cout << "是否开启 ALSR: " << pe_info.HasASLR() << endl;

	pe_info.DisplayPEInfo();
	return 0;
}