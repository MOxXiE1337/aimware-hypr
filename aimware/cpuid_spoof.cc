#include <array>

#include "aimware.h"

#include <hyprtrace/exec_tracer.h>


bool Aimware::SetupCpuidSpoof()
{
	hyprutils::LogManager& logman = GetLogManager();
	static std::array<uintptr_t, 2> cpuid_addresses =
	{
		0x00000011B7F2B241, 0x00000011B7ADEA7C
	};
	static std::unordered_map<uintptr_t, uintptr_t> cpuid_inputs{};

	for (auto& address : cpuid_addresses)
	{
		if (!hyprtrace::ExecutionTracer::AddExecutionBreakPoint(address, 2,
			[](hyprutils::LogManager* logman, PCONTEXT context) 
			{
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
							//logman->Log("spoofed cpuid {:X}, input {:X} -> output {:X} {:X} {:X} {:X}", address, input, context->Rax, context->Rbx, context->Rcx, context->Rdx);
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