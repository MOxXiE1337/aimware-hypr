#include "aimware.h"

#include <hyprtrace/api_tracer.h>
#include <hyprtrace/execbp_tracer.h>

bool Aimware::PrevMap()
{
	hyprutils::LogManager& logman = GetLogManager();
	hypr::RuntimeDump&     dump = GetRuntimeDump();
	hypr::SegmentMapper&   mapper = GetSegmentMapper();

	// load runtime dump
	if (!dump.LoadRuntimeDumpFileFromFile(appdata_path_ + "\\aimware\\aimware.hdmp"))
	{
		logman.Error("failed to load runtime dump file from \"{}\"", appdata_path_ + "\\aimware\\aimware.hdmp");
		return false;
	}

	// load segments 
	if (!mapper.LoadSegmentsFileFromFile(appdata_path_ + "\\aimware\\aimware.hseg"))
	{
		logman.Error("failed to load segments file from \"{}\"", appdata_path_ + "\\aimware\\aimware.hseg");
		return false;
	}

	// set mapper to static mode
	mapper.SetMode(hypr::SegmentMapperMode::kStatic);
	

	return true;
}

bool Aimware::PrevInvoke()
{
	hyprutils::LogManager& logman = GetLogManager();

	hyprtrace::ApiTracer::Intialize(this);
		
	hyprtrace::ApiTracer::AddFilteringModule("msvcrt.dll");

	hyprtrace::ApiTracer::AddFilteringApi("ntdll.dll!RtlEnterCriticalSection");
	hyprtrace::ApiTracer::AddFilteringApi("ntdll.dll!RtlLeaveCriticalSection");
	hyprtrace::ApiTracer::AddFilteringApi("ntdll.dll!NtQueryVirtualMemory");

	hyprtrace::ApiTracer::AddFilteringApi("gdi32.dll!GetTextExtentPoint32W");
	hyprtrace::ApiTracer::AddFilteringApi("gdi32.dll!ExtTextOutW");

	hyprtrace::ApiTracer::AddFilteringApi("kernel32.dll!QueryPerformanceCounter");
	hyprtrace::ApiTracer::AddFilteringApi("kernel32.dll!QueryPerformanceFrequency");

	hyprtrace::ApiTracer::AddFilteringApi("user32.dll!GetClientRect");
	hyprtrace::ApiTracer::AddFilteringApi("user32.dll!IsIconic");
	hyprtrace::ApiTracer::AddFilteringApi("user32.dll!GetCursorPos");
	hyprtrace::ApiTracer::AddFilteringApi("user32.dll!ScreenToClient");
	hyprtrace::ApiTracer::AddFilteringApi("user32.dll!GetForegroundWindow");
	hyprtrace::ApiTracer::AddFilteringApi("user32.dll!CallWindowProcW");

	//ApiTracer] 7FF8AE09FAA0 -> 7FFB23A7FAA0 ntdll.dll!RtlEnterCriticalSection(return to 11B76D97B0)
	//	[ApiTracer] 7FF8AE09F230 -> 7FFB23A7F230 ntdll.dll!RtlLeaveCriticalSection(return to 11B76072CC)

	logman.Log("setting up imports...");
	//if (!SetupImports())
	//{
	//	logman.Error("failed to set up imports");
	//	return false;
	//}
	logman.Log("imports have been set up");

	return true;
}

bool Aimware::Invoke()
{
	hyprutils::LogManager& logman = GetLogManager();

	logman.Log("calling entry point...");
	HANDLE thread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(0x11B75003DD), nullptr, 0, nullptr);

	if (thread)
		CloseHandle(thread);

	return true;
}

bool Aimware::AfterInvoke()
{
	return true;
}



