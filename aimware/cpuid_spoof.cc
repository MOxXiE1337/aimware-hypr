#include <array>

#include "aimware.h"

#include <hyprtrace/exec_tracer.h>


bool Aimware::SetupCpuidSpoof()
{
	hyprutils::LogManager& logman = GetLogManager();

	static std::vector<uintptr_t> cpuid_addresses =
	{
0x11b7564ede,
0x11b75bda52,
0x11b770ba13,
0x11b783f689,
0x11b7858283,
0x11b787bc6a,
0x11b78963d9,
0x11b78a5d88,
0x11b78bd1d3,
0x11b78c302f,
0x11b78d873a,
0x11b78da709,
0x11b78f520b,
0x11b78fccf2,
0x11b79070a6,
0x11b792da5c,
0x11b7940b9f,
0x11b79559a0,
0x11b798f16e,
0x11b79a7318,
0x11b79b14aa,
0x11b79b1dc9,
0x11b7a6a9b3,
0x11b7a9c7c5,
0x11b7ace52e,
0x11b7adea7c,
0x11b7ae2381,
0x11b7aeae11,
0x11b7b0a42d,
0x11b7b20b39,
0x11b7c8ba93,
0x11b7dd02d0,
0x11b7e14988,
0x11b7e16e3c,
0x11b7e8e9bb,
0x11b7f0c5c8,
0x11b7f2b241,
0x11b7f36d97,
0x11b7f40427,
0x11b7f44416,
0x11b7f8e368,
0x11b7fced27,
0x11b801e5a6,
0x11b805af83,
0x11b806a32b,
0x11b8078d0c,
0x11b809796b,
0x11b809fd27,
0x11b80b6723,
0x11b80de62b,
0x11b80fb8cb,
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