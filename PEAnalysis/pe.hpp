#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include <tuple>
#include "utils.hpp"


// 剩下的任务
// 1. 添加新节


// 假定 PE 文件头的大小不超过 4096 个字节
#define MAX_HEADER_LENGTH 4096

enum PEType {
	PE32, PE64
};

typedef struct _PEHeader {
	// mz 文件头
	IMAGE_DOS_HEADER mz_header;
	// 64 位和 32 位某些字段的长度不一样，例如 ImageBase
	// 匿名 union
	union
	{
		IMAGE_NT_HEADERS32 nt_headers32;
		IMAGE_NT_HEADERS64 nt_headers64;
	};
	// 节表
	std::vector<IMAGE_SECTION_HEADER> section_headers;
}PEHeader;


class PEHelper {
private:
	// PE 类型
	PEType type;
	// PE 文件头
	PEHeader header;
	// PE 路径
	std::string path;

	void ReadMZHeader(const BYTE* buffer) {
		// 判断 MZ 文件头
		if (!(buffer[0] == 0x4D && buffer[1] == 0x5A)) {
			std::cerr << "不是MZ文件头" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		std::memcpy(&header.mz_header, buffer, sizeof(IMAGE_DOS_HEADER));
	}

	void GetPEType(const BYTE* buffer) {
		if (buffer[0] == 0x0B) {
			if (buffer[1] == 0x01) {
				type = PE32;
			}
			else if (buffer[1] == 0x02) {
				type = PE64;
			}
			else {
				std::cerr << "PE类型错误" << std::endl;
				std::exit(EXIT_FAILURE);
			}
		}
		else {
			std::cerr << "PE类型错误" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}

	void ReadNTHeaders(const BYTE* buffer) {
		// 判断 PE 文件头
		if (!(buffer[0] == 0x50 && buffer[1] == 0x45)) {
			std::cerr << "不是PE文件" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		// PE 类型位置
		GetPEType(buffer + 24);
		
		switch (type) {
		case PE32: {
			std::memcpy(&header.nt_headers32, buffer, sizeof(IMAGE_NT_HEADERS32));
			break;
		}
		case PE64: {
			std::memcpy(&header.nt_headers64, buffer, sizeof(IMAGE_NT_HEADERS64));
			break;
		}
		default: {
			std::cerr << "不是PE文件" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		}
	}
	void ReadSectionHeader(const BYTE* buffer) {
		header.section_headers.clear();
		for (int i = 0; i != GetSectionsNumber(); i++) {
			IMAGE_SECTION_HEADER section_header;
			std::memcpy(&section_header, buffer + i * 0x28, sizeof(IMAGE_SECTION_HEADER));
			header.section_headers.push_back(section_header);
		}
	}

	void CheckSequenceZero(const BYTE* buffer, int length) {
		if (!IsSequenceZero(buffer, length)) {
			std::cerr << "非零错误" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}

	bool IsSequenceZero(const BYTE* buffer, int length) {
		for (int i = 0; i != length; i++) {
			if (buffer[i] != 0x00) {
				return false;
			}
		}
		return true;
	}

	// 返回以 '0x00' 结尾的字符串，并且移动文件指针
	std::string ReadNextString(std::ifstream &file) {
		std::string name;
		while (true) {
			char c = file.get();
			if (c == 0x00) {
				return name;
			}
			name.push_back(c);
		}
	}

	// 读取文件的下一个双字
	DWORD ReadNextDWORD(std::ifstream& file) {
		BYTE* buffer = new BYTE[sizeof(DWORD) + 1];
		for (int i = 0; i != sizeof(DWORD); i++) {
			buffer[i] = static_cast<BYTE>(file.get());
		}
		DWORD next;
		std::memcpy(&next, buffer, sizeof(DWORD));

		delete[] buffer;
		return next;
	}

	// 读取文件的下一个字
	WORD ReadNextWORD(std::ifstream& file) {
		BYTE* buffer = new BYTE[sizeof(WORD) + 1];
		for (int i = 0; i != sizeof(WORD); i++) {
			buffer[i] = static_cast<BYTE>(file.get());
		}
		WORD next;
		std::memcpy(&next, buffer, sizeof(WORD));

		delete[] buffer;
		return next;
	}

	// 写文件的下一个字
	void WriteNextWORD(std::ofstream& file, WORD word) {
		CHAR* buffer = new CHAR[sizeof(WORD) + 1];
		std::memcpy(buffer, &word, sizeof(WORD));

		if (!file.write(buffer, sizeof(WORD))) {
			std::cerr << "写入文件失败" << std::endl;
			std::exit(EXIT_FAILURE);
		}

		delete[] buffer;
	}

public:
	void ReadPEHeaderByName(std::string pe_path) {
		path = pe_path;

		std::ifstream file(pe_path, std::ios::binary);
		// 读入文件头到缓冲区当中
		BYTE* buffer = new BYTE[MAX_HEADER_LENGTH];
		// c++ 为啥二进制是 char？
		int i = 0;
		while (file.good() && i < MAX_HEADER_LENGTH) {
			buffer[i] = file.get();
			i++;
		}
		ReadMZHeader(buffer);
		ReadNTHeaders(buffer + GetNTHeaderFOA());
		ReadSectionHeader(buffer + GetSectionHeaderFOA());

		file.close();
		delete[] buffer;
	}

	WORD GetSectionsNumber() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.FileHeader.NumberOfSections;
		}
		case PE64: {
			return header.nt_headers64.FileHeader.NumberOfSections;
		}
		}
	}

	DWORD GetNTHeaderFOA() {
		return header.mz_header.e_lfanew;
	}

	DWORD GetOptionalHeaderFOA() {
		return GetNTHeaderFOA() + 24;
	}

	DWORD GetSectionHeaderFOA() {
		return GetNTHeaderFOA() + IMAGE_SIZEOF_FILE_HEADER + GetSizeOfOptionalHeader() + 4;
	}

	WORD GetSizeOfOptionalHeader() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.FileHeader.SizeOfOptionalHeader;
		}
		case PE64: {
			return header.nt_headers64.FileHeader.SizeOfOptionalHeader;
		}
		}
	}

	DWORD GetSizeOfCode() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.SizeOfCode;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.SizeOfCode;
		}
		}
	}

	DWORD GetSizeOfHeaders() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.SizeOfHeaders;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.SizeOfHeaders;
		}
		}
	}

	DWORD GetEntryPointRVA() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.AddressOfEntryPoint;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.AddressOfEntryPoint;
		}
		}
	}

	DWORD GetEntryPointFOA() {
		return RVAToFOA(GetEntryPointRVA());
	}

	DWORD GetBaseOfCodeRVA() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.BaseOfCode;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.BaseOfCode;
		}
		}
	}

	ULONGLONG GetImageBase() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.ImageBase;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.ImageBase;
		}
		}
	}

	DWORD GetSectionAlignment() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.SectionAlignment;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.SectionAlignment;
		}
		}
	}

	DWORD GetFileAlignment() {
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.FileAlignment;
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.FileAlignment;
		}
		}
	}

	DWORD RVAToFOA(DWORD rva) {
		// TODO
		// 这里假定 rva 小于一个文件对齐时必然位于头部
		if (rva < GetSectionAlignment()) {
			return rva;
		}
		// 遍历每一个节
		for (auto it = header.section_headers.begin() + 1; it != header.section_headers.end(); it++) {
			if (rva < it->VirtualAddress) {
				it--;
				// 利用 FOA 之间的差值等于 RVA 之间的差值
				return it->PointerToRawData + rva - it->VirtualAddress;
			}
		}
		std::cerr << "RVA超过界限" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	// TODO
	// 这里有点奇怪，VirtualAddress 似乎不会超过 DWORD
	// 先不考虑 rva 是 ULONGLONG 的情况吧
	//ULONGLONG RVAToFOA(ULONGLONG rva) {
	//	// TODO
	//	// 这里假定 rva 小于一个文件对齐时必然位于头部
	//	if (rva < GetSectionAlignment()) {
	//		return rva;
	//	}
	//	// 遍历每一个节
	//	for (auto it = header.section_headers.begin() + 1; it != header.section_headers.end(); it++) {
	//		if (rva < it->VirtualAddress) {
	//			it--;
	//			// 利用 FOA 之间的差值等于 RVA 之间的差值
	//			return it->PointerToRawData + rva - it->VirtualAddress;
	//		}
	//	}
	//	std::cerr << "RVA超过界限" << std::endl;
	//	std::exit(EXIT_FAILURE);
	//}

	std::vector<std::string> GetSectionNames() {
		std::vector<std::string> names;
		for (auto it = header.section_headers.begin(); it != header.section_headers.end(); it++) {
			std::string name(8, 0);
			for (int i = 0; i != 8; i++) {
				name[i] = static_cast<char>(it->Name[i]);
			}
			names.push_back(name);
		}

		return names;
	}

	// TODO
	// 64 位的导出表和 32 位的是否一样?
	// 通过函数名查找导出地址
	DWORD GetExportFunctionRVA(std::string name) {
		IMAGE_EXPORT_DIRECTORY export_directory = GetExportDirectory();
		DWORD names_foa = RVAToFOA(export_directory.AddressOfNames);
		DWORD ordinals_foa = RVAToFOA(export_directory.AddressOfNameOrdinals);
		DWORD address_foa = RVAToFOA(export_directory.AddressOfFunctions);

		std::ifstream file(path, std::ios::binary);
		// AddressOfNames 中的索引
		DWORD index = 0;
		for (index; index != export_directory.NumberOfNames; index++) {
			file.seekg(names_foa + index * sizeof(DWORD), std::ios::beg);
			// 指向函数名
			DWORD name_foa = RVAToFOA(ReadNextDWORD(file));
			file.seekg(name_foa, std::ios::beg);
			std::string function_name = ReadNextString(file);
			if (function_name == name) {
				break;
			}
		}
		if (index == export_directory.NumberOfNames) {
			std::cerr << "找不到相应的导出函数" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		// 找到 AddressOfNameOrdianls 中该索引对应的序号
		file.seekg(ordinals_foa + sizeof(WORD) * index, std::ios::beg);
		WORD ordinal_index = ReadNextWORD(file);
		
		// 在 AddressOfFunctions 中找到对应的 RVA
		file.seekg(address_foa + sizeof(DWORD) * ordinal_index, std::ios::beg);
		DWORD function_rva = ReadNextDWORD(file);

		file.close();
		return function_rva;
	}

	std::vector<IMAGE_IMPORT_DESCRIPTOR> GetImageImportDescriptors() {
		IMAGE_DATA_DIRECTORY import_entry = GetImageDataDirectorEntry(IMAGE_DIRECTORY_ENTRY_IMPORT);
		DWORD import_entry_rva = import_entry.VirtualAddress;
		DWORD import_entry_size = import_entry.Size;
		DWORD import_descriptor_num = import_entry_size / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1;
		DWORD import_entry_foa = RVAToFOA(import_entry_rva);

		std::ifstream file(path, std::ios::binary);
		file.seekg(import_entry_foa, std::ios::beg);
		// 将 image_import_descriptor 存入缓冲区中
		BYTE* buffer = new BYTE[import_entry_size+1];
		for (DWORD i = 0; i <= import_entry_size; i++) {
			buffer[i] = static_cast<BYTE>(file.get());
		}
		file.close();

		std::vector<IMAGE_IMPORT_DESCRIPTOR> import_descriptor_vector;
		for (int i = 0; i != import_descriptor_num; i++) {
			IMAGE_IMPORT_DESCRIPTOR import_descriptor;
			std::memcpy(&import_descriptor, buffer + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR));
			import_descriptor_vector.push_back(import_descriptor);
		}
		// 检查是否是 0 结束
		CheckSequenceZero(buffer + import_descriptor_num * sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR));
		delete[] buffer;
		return import_descriptor_vector;
	}

	// 返回所有导入的 dll 名字
	std::vector<std::string> GetImportDLLNames() {
		std::vector<std::string> names;

		std::ifstream file(path, std::ios::binary);
		std::vector<IMAGE_IMPORT_DESCRIPTOR> import_descriptor_vector = GetImageImportDescriptors();
		for (auto it = import_descriptor_vector.begin(); it != import_descriptor_vector.end(); it++) {
			DWORD name_rva = it->Name;
			DWORD name_foa = RVAToFOA(name_rva);
			file.seekg(name_foa, std::ios::beg);
			names.push_back(ReadNextString(file));
		}

		file.close();
		return names;
	}

	// 导出目录
	IMAGE_EXPORT_DIRECTORY GetExportDirectory() {
		IMAGE_DATA_DIRECTORY export_entry = GetImageDataDirectorEntry(IMAGE_DIRECTORY_ENTRY_EXPORT);
		DWORD export_rva = export_entry.VirtualAddress;
		if (export_rva == 0 || export_entry.Size == 0) {
			std::cerr << "没有导出目录表" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		DWORD export_foa = RVAToFOA(export_rva);
		std::ifstream file(path, std::ios::binary);
		file.seekg(export_foa, std::ios::beg);

		IMAGE_EXPORT_DIRECTORY export_directory;
		BYTE* buffer = new BYTE[sizeof(IMAGE_EXPORT_DIRECTORY) + 1];
		for (int i = 0; i != sizeof(IMAGE_EXPORT_DIRECTORY); i++) {
			buffer[i] = static_cast<BYTE>(file.get());
		}
		std::memcpy(&export_directory, buffer, sizeof(IMAGE_EXPORT_DIRECTORY));

		file.close();
		delete[] buffer;
		return export_directory;
	}

	// TODO
	// 这样写实在是太丑了，以后一定要试试泛型
	// 返回函数序号和对应的函数名
	std::vector<std::tuple<WORD, std::string>> GetImportFunctionNames(IMAGE_IMPORT_DESCRIPTOR descriptor) {
		std::vector<std::tuple<WORD, std::string>> result;

		std::ifstream file(path, std::ios::binary);
		// 存储序号的 buffer
		BYTE* buffer = new BYTE[sizeof(WORD) + 1];

		switch (type) {
		case PE32: {
			std::vector<IMAGE_THUNK_DATA32> thunk_data32 = GetImageThunkData32(descriptor);
			for (auto it = thunk_data32.begin(); it != thunk_data32.end(); it++) {
				// 如果最高位是 1，表示以序号类型导入
				if (it->u1.Ordinal & 0x10000000) {
					std::cout << "以序号类型导入，不支持获取函数名" << std::endl;
				}
				// 否则是一个指向 IMAGE_IMPORT_BY_NAME 的 rva
				else {
					DWORD foa = RVAToFOA(it->u1.AddressOfData);
					file.seekg(foa, std::ios::beg);

					for (int i = 0; i != sizeof(WORD); i++) {
						buffer[i] = static_cast<BYTE>(file.get());
					}
					// 函数序号
					WORD hint;
					std::memcpy(&hint, buffer, sizeof(WORD));
					std::string name = ReadNextString(file);
					result.push_back(std::make_tuple(hint, name));
				}
			}
			break;
		}
		// 复制一遍太蠢了
		case PE64: {
			std::vector<IMAGE_THUNK_DATA64> thunk_data64 = GetImageThunkData64(descriptor);
			for (auto it = thunk_data64.begin(); it != thunk_data64.end(); it++) {
				// 如果最高位是 1，表示以序号类型导入
				if (it->u1.Ordinal & 0x10000000) {
					std::cout << "以序号类型导入，不支持获取函数名" << std::endl;
				}
				// 否则是一个指向 IMAGE_IMPORT_BY_NAME 的 rva
				else {
					DWORD foa = RVAToFOA(it->u1.AddressOfData);
					file.seekg(foa, std::ios::beg);
					for (int i = 0; i != sizeof(WORD) + 1; i++) {
						buffer[i] = static_cast<BYTE>(file.get());
					}
					// 函数序号
					WORD hint;
					std::memcpy(&hint, buffer, sizeof(WORD));
					std::string name = ReadNextString(file);
					result.push_back(std::make_tuple(hint, name));
				}
			}
			break;
		}
		}
		delete[] buffer;
		file.close();
		return result;
	}

	// TODO
	// 由于在文件中 IAT 和 INT 表的内容一样，因此我们只从 IAT 中读
	std::vector<IMAGE_THUNK_DATA64> GetImageThunkData64(IMAGE_IMPORT_DESCRIPTOR descriptor) {
		std::vector<IMAGE_THUNK_DATA64> thunk_vector;
		DWORD thunk_rva = descriptor.FirstThunk;
		DWORD thunk_foa = RVAToFOA(thunk_rva);

		std::ifstream file(path, std::ios::binary);
		file.seekg(thunk_foa, std::ios::beg);
		// 存储 thunk 的缓冲区
		BYTE* buffer = new BYTE[sizeof(IMAGE_THUNK_DATA64) + 1];
		IMAGE_THUNK_DATA64 thunk;
		while (true) {
			for (int i = 0; i < sizeof(IMAGE_THUNK_DATA64); i++) {
				buffer[i] = static_cast<BYTE>(file.get());
			}
			if (IsSequenceZero(buffer, sizeof(IMAGE_THUNK_DATA64))) {
				return thunk_vector;
			}
			std::memcpy(&thunk, buffer, sizeof(IMAGE_THUNK_DATA64));
			thunk_vector.push_back(thunk);
		}
	}

	std::vector<IMAGE_THUNK_DATA32> GetImageThunkData32(IMAGE_IMPORT_DESCRIPTOR descriptor) {
		std::vector<IMAGE_THUNK_DATA32> thunk_vector;
		DWORD thunk_rva = descriptor.FirstThunk;
		DWORD thunk_foa = RVAToFOA(thunk_rva);

		std::ifstream file(path, std::ios::binary);
		file.seekg(thunk_foa, std::ios::beg);
		// 存储 thunk 的缓冲区
		BYTE* buffer = new BYTE[sizeof(IMAGE_THUNK_DATA32) + 1];
		IMAGE_THUNK_DATA32 thunk;
		while (true) {
			for (int i = 0; i < sizeof(IMAGE_THUNK_DATA32); i++) {
				buffer[i] = static_cast<BYTE>(file.get());
			}
			if (IsSequenceZero(buffer, sizeof(IMAGE_THUNK_DATA32))) {
				return thunk_vector;
			}
			std::memcpy(&thunk, buffer, sizeof(IMAGE_THUNK_DATA32));
			thunk_vector.push_back(thunk);
		}
	}

	IMAGE_DATA_DIRECTORY GetImageDataDirectorEntry(UINT32 index) {
		if (index < 0 || index > 15) {
			std::cerr << "超过索引范围" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		switch (type) {
		case PE32: {
			return header.nt_headers32.OptionalHeader.DataDirectory[index];
		}
		case PE64: {
			return header.nt_headers64.OptionalHeader.DataDirectory[index];
		}
		}
	}

	// ASLR 位于可选文件头的 DLL Characteristics
	// https://www.jianshu.com/p/91b2b6665e64
	bool HasASLR() {
		switch (type) {
		case PE32: {
			if (header.nt_headers32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
				return true;
			}
			return false;
		}
		case PE64: {
			if (header.nt_headers64.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
				return true;
			}
			return false;
		}
		}
	}
	
	// DLLCharacteristics 在 64 位和 32 位 PE 文件中与 Optional header 的偏移是相同的，都是 70
	void ASLRAction(bool if_close) {
		// 注意如果是 fstream 需要指定打开的属性
		std::ifstream file_in(path, std::ios::binary);
		WORD dll_characteristics;

		// 定位到 DllCharacteristics
		DWORD dll_characteristics_foa = GetOptionalHeaderFOA() + 70;
		file_in.seekg(dll_characteristics_foa, std::ios::beg);
		dll_characteristics = ReadNextWORD(file_in);
		file_in.close();
		if (if_close) dll_characteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		else dll_characteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		// 太坑爹了吧，C艹真的难用
		// 注意先关闭读取文件，并且使用追加模式打开
		std::ofstream file_out(path, std::ios::binary || std::ios::app);
		file_out.seekp(dll_characteristics_foa, std::ios::beg);
		WriteNextWORD(file_out, dll_characteristics);
		file_out.close();

		// 重新导入
		ReadPEHeaderByName(path);
	}
	void CloseASLR() {
		ASLRAction(true);
	}

	void OpenASLR() {
		ASLRAction(false);
	}

	void DisplayPEInfo() {
		std::cout << "========================================================================\n\n";
		std::cout << "PE文件路径: " << path << "\n";
		std::cout << "程序入口点RVA: " << GetEntryPointRVA() << ", FOA: " << GetEntryPointFOA() << "\n";
		std::cout << "文件对齐: " << GetFileAlignment() << "\n";
		std::cout << "内存对齐: " << GetSectionAlignment() << "\n";
		std::cout << "节数量: " << GetSectionsNumber() << "\n";
		std::cout << "节信息: \n";
		for (auto it = header.section_headers.begin(); it != header.section_headers.end(); it++) {
			std::cout << "--------------------------\n";
			std::cout << "节名: " << it->Name << "\n";
			std::cout << "节大小: " << it->SizeOfRawData << "\n";
			std::cout << "节起始RVA: " << it->VirtualAddress << "\n";
			std::cout << "节起始FOA: " << it->PointerToRawData << "\n";
			std::cout << "--------------------------\n";
		}
		std::cout << "========================================================================\n" << std::endl;
	}
};
