#pragma once
#include <Windows.h>
#include <fstream>

void CheckSequenceZero(const BYTE* buffer, int length);
bool IsSequenceZero(const BYTE* buffer, int length);
std::string ReadNextString(std::ifstream& file);
DWORD ReadNextDWORD(std::ifstream& file);
WORD ReadNextWORD(std::ifstream& file);
void WriteNextWORD(std::ofstream& file, WORD word);
void WriteNextDWORD(std::ofstream& file, DWORD dword);
void WriteBuffer(std::ofstream& file, const CHAR* buffer, ULONGLONG size);