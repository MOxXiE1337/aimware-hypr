#include "aimware.h"

bool Aimware::SetupImports()
{
	// based on hyprocess
	hyprutils::LogManager& logman = GetLogManager();
	hypr::RuntimeDump& dump = GetRuntimeDump();

	// check memory regions
	for (auto& module : dump.GetModuleRecords())
	{
		MEMORY_BASIC_INFORMATION mbi{};

		if (!VirtualQuery(reinterpret_cast<LPCVOID>(module->imagebase), &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			logman.Error("memory region for {} is invalid", module->name);
			return false;
		}

		if (mbi.RegionSize != module->imagesize)
		{
			logman.Error("memory region for {} is invalid", module->name);
			return false;
		}
	}

	std::vector<std::string> modules_required =
	{
		"kernel32.dll",
		"ntdll.dll",
		"msvcrt.dll",
		"user32.dll",
		"gdi32.dll",
		"shell32.dll"
	};
	
	// setup procs, takes time...
	for (auto& mod_name : modules_required)
	{	
		auto module = dump.FindModuleRecord(mod_name);
		for (auto& proc : module->procs)
		{
			if (proc->name.empty())
				continue;

	
			if (!proc->LoadProc())
			{
				logman.Warn("failed to load proc {}!{}", module->name, proc->name);
				continue;
			}

			*reinterpret_cast<uint64_t*>(proc->address) = 0x00000000000025FF;
			*reinterpret_cast<uintptr_t*>(proc->address + 6) = proc->new_address;
		}
	}

	return true;
}