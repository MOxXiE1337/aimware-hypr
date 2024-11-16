#define _CRT_SECURE_NO_WARNINGS 1

#include "minhdmp.h"
#include "minhseg.h"

#include <print>

#include <hyprfile/runtime_dump_file.h>
#include <hyprfile/segments_file.h>

#include <hyprocess/process_starter.h>

int main(int argc, char* argv[])
{
	hyprocess::ProcessStarter ps{};
	hyprfile::RuntimeDumpFile runtime_dump{};
	hyprfile::SegmentsFile segments{};

	hyprutils::LogManager& logman = ps.GetLogManager();

	HKEY key;
	char install_path[MAX_PATH];
	DWORD buffer_size = MAX_PATH;
	
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\cs2", 0, KEY_READ, &key) != ERROR_SUCCESS)
	{
		logman.Error("failed to find registry");
		return -1;
	}

	if (RegQueryValueExA(key, "installpath", nullptr, nullptr, reinterpret_cast<LPBYTE>(install_path), &buffer_size) != ERROR_SUCCESS)
	{
		logman.Error("failed to fetch registry");
		RegCloseKey(key);
		return -1;
	}

	RegCloseKey(key);

	std::string cs2_path = std::string(install_path) + "\\game\\bin\\win64\\cs2.exe";

	logman.Log("cs2 path: {}", cs2_path);

	if (!runtime_dump.LoadFromMemory(minhdmp, sizeof(minhdmp)))
	{
		logman.Error("failed to load runtime dump file");
		system("pause");
		return -1;
	}
	if (!segments.LoadFromMemory(minhseg, sizeof(minhseg)))
	{
		logman.Error("failed to load segments file");
		system("pause");
		return -1;
	}

	ps.ReserveMemoryFromRuntimeDumpFile(runtime_dump);
	ps.ReserveMemoryFromSegmentsFile(segments);
	
	ps.SetImagePath(cs2_path);
	ps.SetCommandLineParameters("-worldwide -insecure");

	HANDLE process = NULL;
	size_t try_num = 0;

	while (try_num < 10)
	{
		logman.DisableLogging();
		process = ps.StartProcess();
		logman.EnableLogging();

		if (process != NULL)
			break;

		try_num++;
		logman.Log("retrying... ({}/10)", try_num);
	}

	if (try_num >= 10)
	{
		system("pause");
	}
	else
	{
		logman.Log("process started {:X}", reinterpret_cast<uintptr_t>(process));
	}

	return 0;
}
