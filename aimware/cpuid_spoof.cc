#include <array>

#include "aimware.h"

#include <hyprtrace/exec_tracer.h>


bool Aimware::SetupCpuidSpoof()
{
	hyprutils::LogManager& logman = GetLogManager();

	static std::vector<uintptr_t> cpuid_addresses =
	{
0x11B7F2B241, // 1
0x11B7ADEA7C, // 2
0x11B78F520B, // 3
0x11B78A5D88, // 4
0x11B7940B9F, // 5
0x11B7AE2381, // 6
0x11B7E14988, // 7
0x11B7564EDE, // 8
0x11B801E5A6, // 9
0x11B805AF83, // 10
0x11B7F44416, // 11
0x11B7E8E9BB, // 12
0x11B7F0C5C8, // 13
0x11B7FCED27, // 14
0x11B783F689, // 15
0x11B78DA709, // 16
0x11B80B6723, // 17
0x11B806A32B, // 18
0x11B8078D0C, // 19
0x11B78BD1D3, // 20
0x11B80FB8CB, // 21
0x11B79559A0, // 22
0x11B75BDA52, // 23
0x11B7858283, // 24
0x11B770BA13, // 25
0x11B798F16E, // 26
0x11B78FCCF2, // 27
0x11B79B14AA, // 28
0x11B787BC6A, // 29
0x11B78963D9, // 30
0x11B79A7318, // 31
0x11B792DA5C, // 32
0x11B79070A6, // 33
0x11B79B1DC9, // 34
0x11B7ACE52E, // 35
0x11B7B0A42D, // 36
0x11B7A9C7C5, // 37
0x11B7A6A9B3, // 38
0x11B7AEAE11, // 39
0x11B7B20B39, // 40
0x11B7F36D97, // 41
0x11B7F8E368, // 42
0x11B7F40427, // 43
0x11B809796B, // 44
0x11B809FD27, // 45
0x11B80DE62B, // 46
0x11B7DD02D0, // 47
0x11B7C8BA93, // 48
0x11B7E16E3C, // 49
	};

	static std::unordered_map<uintptr_t, uintptr_t> cpuid_inputs{};

	for (auto& address : cpuid_addresses)
	{
		if (!hyprtrace::ExecutionTracer::AddExecutionBreakPoint(address, 2,
			[](hyprutils::LogManager* logman, PCONTEXT context) 
			{
				static std::mutex lock{};
				std::lock_guard guard{ lock };

				if (context->Rax == 0x80000002 || context->Rax == 0x80000003 || context->Rax == 0x80000004)
				{
					if (cpuid_inputs.find(context->Rip) == cpuid_inputs.end())
						logman->Log("spoofed cpuid {:X} ({}/{})", context->Rip, cpuid_inputs.size() + 1, cpuid_addresses.size());
				}

				cpuid_inputs[context->Rip] = context->Rax;
			},
			[](hyprutils::LogManager* logman, PCONTEXT context)
			{
				uintptr_t address = context->Rip - 2;
				auto it = cpuid_inputs.find(address);
				if (it != cpuid_inputs.end())
				{
					uintptr_t input = it->second;
					auto print_cpuid_spoof = [&]()
						{
							//logman->Log("spoofed cpuid {:X}, input {:X} -> output {:X} {:X} {:X} {:X}", address, input, context->Rax, context->Rbx, context->Rcx, context->Rdx, cpuid_inputs.size(), cpuid_addresses.size());
						};

					switch (input)
					{
					case 0x80000002:
						context->Rax = 0x20444D41;
						context->Rbx = 0x657A7952;
						context->Rcx = 0x2037206E;
						context->Rdx = 0x30303735;
						print_cpuid_spoof();
						break;
					case 0x80000003:
						context->Rax = 0x2D382058;
						context->Rbx = 0x65726F43;
						context->Rcx = 0x6F725020;
						context->Rdx = 0x73736563;
						print_cpuid_spoof();
						break;
					case 0x80000004:
						context->Rax = 0x2020726F; 
						context->Rbx = 0x20202020;
						context->Rcx = 0x20202020;
						context->Rdx = 0x202020; 
						print_cpuid_spoof();
						break;
					default:
						logman->Error("failed to spoof cpuid {:X}, input {:X}", address, input);
						std::exit(-1); // exit process
						break;
					}
				}
			}
		))
		{
			return false;
		}
	}

	return true;
}