#include "utils.hpp"
#include <iostream>
#include <fstream>

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
std::string ReadNextString(std::ifstream& file) {
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