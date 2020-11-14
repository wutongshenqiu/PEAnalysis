#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <map>
#include <tuple>


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
			std::cerr << "字写入文件失败" << std::endl;
			std::exit(EXIT_FAILURE);
		}

		delete[] buffer;
	}

	// 写文件的下一个双字
	void WriteNextDWORD(std::ofstream& file, DWORD dword) {
		CHAR* buffer = new CHAR[sizeof(DWORD) + 1];
		std::memcpy(buffer, &dword, sizeof(DWORD));

		if (!file.write(buffer, sizeof(DWORD))) {
			std::cerr << "双字写入文件失败" << std::endl;
			std::exit(EXIT_FAILURE);
		}

		delete[] buffer;
	}

	// 将缓冲区中 size 大小的数据写入文件
	void WriteBuffer(std::ofstream& file, const CHAR* buffer, ULONGLONG size) {
		if (!file.write(buffer, size)) {
			std::cerr << "缓冲区写入文件失败" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}

	// 在字符串后补零，使其按照文件对其
	void ToFileAlignment(std::string& str) {
		DWORD append_num = str.size() % GetFileAlignment();
		if (append_num) {
			append_num = GetFileAlignment() - append_num;
		}
		for (DWORD i = 0; i != append_num; i++) {
			str.push_back(0x00);
		}
	}


	// 返回内存对齐后的大小
	DWORD ToSectionAlignment(DWORD size) {
		// 按照内存对齐
		DWORD section_alignment = GetSectionAlignment();
		if (size % section_alignment) {
			return (1 + (size / section_alignment)) * section_alignment;
		}
		return size;
	}

public:
	void LoadPE(std::string pe_path) {
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

	// 获取节数量
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

	// NT映像头 FOA
	DWORD GetNTHeaderFOA() {
		return header.mz_header.e_lfanew;
	}

	// 返回可选文件头起始 FOA
	DWORD GetOptionalHeaderFOA() {
		return GetNTHeaderFOA() + 24;
	}

	// 返回节表头起始 FOA
	DWORD GetSectionHeaderFOA() {
		return GetNTHeaderFOA() + IMAGE_SIZEOF_FILE_HEADER + GetSizeOfOptionalHeader() + 4;
	}

	// 返回节表头的末尾 FOA
	DWORD GetEndSectionHeaderFOA() {
		return IMAGE_SIZEOF_SECTION_HEADER * GetSectionsNumber() + GetSectionHeaderFOA();
	}

	// 如果要新增加节，则该节起始的 FOA
	// TODO
	// 这里有个问题
	// 对于某些文件(user32.dll)，节的末尾不是文件的末尾
	// 似乎是 certification table
	ULONGLONG GetNewSectionFOA() {
		// 确保没有 Certification table
		IMAGE_DATA_DIRECTORY certification_table = GetImageDataDirectorEntry(IMAGE_DIRECTORY_ENTRY_SECURITY);
		if (certification_table.Size || certification_table.VirtualAddress) {
			std::cerr << "不支持在有 Certification Table 的PE文件中新增节" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		ULONGLONG file_size = GetFileSize();
		if (file_size % GetFileAlignment()) {
			std::cerr << "奇怪的错误，文件大小不遵照文件对齐" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		return file_size;
	}

	// 新节的起始 RVA
	ULONGLONG GetNewSectionRVA() {
		// 确保没有 Certification table
		IMAGE_DATA_DIRECTORY certification_table = GetImageDataDirectorEntry(IMAGE_DIRECTORY_ENTRY_SECURITY);
		if (certification_table.Size || certification_table.VirtualAddress) {
			std::cerr << "不支持在有 Certification Table 的PE文件中新增节" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		// 遍历节头找到最后一个节
		int last_header_index = 0;
		for (int i = 1; i < header.section_headers.size(); i++) {
			if (header.section_headers[i].VirtualAddress > header.section_headers[last_header_index].VirtualAddress) {
				last_header_index = i;
			}
		}
		DWORD last_header_rva = header.section_headers[last_header_index].VirtualAddress;
		DWORD last_header_size = header.section_headers[last_header_index].SizeOfRawData;
		// 按照内存对齐
		return last_header_rva + ToSectionAlignment(last_header_size);
	}

	// 返回文件的大小
	ULONGLONG GetFileSize() {
		return std::filesystem::file_size(path);
	}

	// 返回可选文件头的大小
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

	// 返回代码段的大小
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

	// 返回头部(包括MZ头、DOS Stub、NT映像头和节表)的大小
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

	// 程序入口 RVA
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

	// 设置程序入口点
	void SetEntryPoint(DWORD entry_point) {
		std::ofstream file(path, std::ios::binary || std::ios::ate);
		// 64 位和 32 位的偏移相等
		file.seekp(GetOptionalHeaderFOA() + 16, std::ios::beg);
		
		WriteNextDWORD(file, entry_point);

		file.close();
	}

	// 程序入口点对应 FOA
	DWORD GetEntryPointFOA() {
		return RVAToFOA(GetEntryPointRVA());
	}
	
	// 代码段 RVA
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
	
	// 内存对齐
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

	// 节对齐
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

	// 获取所有节的名称
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

	// 获取所有的 Import Descriptor
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

	// 所有的 thunk data
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
		LoadPE(path);
	}
	void CloseASLR() {
		ASLRAction(true);
	}

	void OpenASLR() {
		ASLRAction(false);
	}

	IMAGE_SECTION_HEADER CreateNewSectionHeader(
		const BYTE* name,
		const DWORD characteristics = 0,
		const DWORD rva = 0,
		const DWORD foa = 0,
		const DWORD size = 0,
		const DWORD misc = 0,
		const DWORD pointer_to_relocations = 0,
		const WORD pointer_to_linenumbers = 0,
		const WORD number_of_relocations = 0,
		const WORD number_of_linenumbers = 0
	) {
		IMAGE_SECTION_HEADER header;
		std::memcpy(&header.Name, name, IMAGE_SIZEOF_SHORT_NAME);
		std::memcpy(&header.Misc, &misc, sizeof(DWORD));
		header.VirtualAddress = rva;
		header.SizeOfRawData = size;
		header.PointerToRawData = foa;
		header.PointerToRelocations = pointer_to_relocations;
		header.PointerToLinenumbers = pointer_to_linenumbers;
		header.NumberOfRelocations = number_of_relocations;
		header.NumberOfLinenumbers = number_of_linenumbers;
		header.Characteristics = characteristics;
		
		return header;
	}

	// 添加一个新节
	// 包括以下步骤
	//		1. 在文件末尾追加写一个新节(需要注意不满足文件对齐的部分要补零)
	//		2. 在节表中新增一个节头
	//		3. 增加 FILE_HEADER 中的 NumberOfSections 字段
	//		4. 调整可选文件头中的 SizeOfImage
	void AddNewSection(
		std::string buffer,
		const BYTE* name,
		// 默认权限为可写可执行代码
		const DWORD characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
	) {
		std::ofstream file(path, std::ios::binary || std::ios::ate);
		
		// 补零使得文件对齐
		ToFileAlignment(buffer);
		
		// 初始化节头
		// 不能跳过默认参数太蠢了
		IMAGE_SECTION_HEADER section_header = CreateNewSectionHeader(name, characteristics, GetNewSectionRVA(), GetNewSectionFOA(), buffer.size());
		
		// 写入新节的步骤需要在创建节头之后
		file.seekp(GetNewSectionFOA(), std::ios::beg);
		// 在文件的末尾写入新节
		WriteBuffer(file, buffer.c_str(), buffer.size());
		// 直接写入文件，用于调试
		//file.flush();

		// 定位到节表头的末尾
		file.seekp(GetEndSectionHeaderFOA(), std::ios::beg);
		// 将节表头的内容放到到缓冲区当中
		CHAR* header_buffer = new CHAR[IMAGE_SIZEOF_SECTION_HEADER + 1];
		std::memcpy(header_buffer, &section_header, IMAGE_SIZEOF_SECTION_HEADER);
		// 写入节表头
		WriteBuffer(file, header_buffer, IMAGE_SIZEOF_SECTION_HEADER);
		delete[] header_buffer;

		switch (type) {
		case PE32: {
			// 定位到 NumberOfSections 字段
			file.seekp(GetNTHeaderFOA() + 6, std::ios::beg);
			WORD new_section_number = header.nt_headers32.FileHeader.NumberOfSections + 1;
			WriteNextWORD(file, new_section_number);
			// 增加新节后在内存中的大小
			DWORD new_image_size = header.nt_headers32.OptionalHeader.SizeOfImage + ToSectionAlignment(section_header.SizeOfRawData);
			// 定位到 SizeofImage 字段
			file.seekp(GetOptionalHeaderFOA() + 56, std::ios::beg);
			WriteNextDWORD(file, new_image_size);
			break;
		}
		case PE64: {
			// 定位到 NumberOfSections 字段
			file.seekp(GetNTHeaderFOA() + 6, std::ios::beg);
			WORD new_section_number = header.nt_headers64.FileHeader.NumberOfSections + 1;
			WriteNextWORD(file, new_section_number);
			// 增加新节后在内存中的大小
			DWORD new_image_size = header.nt_headers64.OptionalHeader.SizeOfImage + ToSectionAlignment(section_header.SizeOfRawData);
			// 定位到 SizeofImage 字段
			file.seekp(GetOptionalHeaderFOA() + 56, std::ios::beg);
			WriteNextDWORD(file, new_image_size);
			break;
		}
		}

		file.close();
	}

	void DisplayPEInfo() {
		std::cout << "========================================================================\n\n";
		std::cout << "PE文件路径: " << path << "\n";
		std::cout << "文件大小: " << GetFileSize() << "\n";
		std::cout << "ImageBase: " << GetImageBase() << "\n";
		std::cout << "程序入口点RVA: " << GetEntryPointRVA() << ", FOA: " << GetEntryPointFOA() << "\n";
		std::cout << "文件对齐: " << GetFileAlignment() << "\n";
		std::cout << "内存对齐: " << GetSectionAlignment() << "\n";
		std::cout << "文件头占磁盘大小: " << GetSizeOfHeaders() << "\n";
		std::cout << "文件头实际大小(节表头末尾): " << GetEndSectionHeaderFOA() << "\n\n";
		std::cout << "节信息: \n";
		std::cout << "节数量: " << GetSectionsNumber() << "\n";
		std::cout << "节表头起始FOA: " << GetSectionHeaderFOA() << "\n";
		std::cout << "节表头末尾FOA: " << GetEndSectionHeaderFOA() << "\n";
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
