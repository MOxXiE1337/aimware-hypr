#include "aimware.h"

#include <hyprtrace/api_tracer.h>
#include <hyprtrace/exec_tracer.h>

LONG NTAPI Aimware::ExceptionHandler(struct _EXCEPTION_POINTERS* exception)
{
	MessageBoxA(NULL, std::format("exception {:X} not handled at {:X}", exception->ExceptionRecord->ExceptionCode, reinterpret_cast<uintptr_t>(exception->ExceptionRecord->ExceptionAddress)).c_str(), "Aimware Error", MB_ICONERROR);
	return EXCEPTION_CONTINUE_SEARCH;
}

bool Aimware::PrevMap()
{
	hyprutils::LogManager& logman = GetLogManager();
	hypr::RuntimeDump&     dump = GetRuntimeDump();
	hypr::SegmentMapper&   mapper = GetSegmentMapper();

	AddVectoredExceptionHandler(0, ExceptionHandler);

	cfg_path_ = std::wstring(_wgetenv(L"APPDATA")) + L"\\aimware\\cfg\\";

	if (!std::filesystem::exists(cfg_path_))
	{
		std::filesystem::create_directories(cfg_path_);
		logman.Log("created config folder {}", std::string(cfg_path_.begin(), cfg_path_.end()));
	}

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
	hyprtrace::ExecutionTracer::Initialize();

	hyprtrace::ApiTracer::DisableTraceLogging();

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
	if (!SetupImports())
	{
		logman.Error("failed to set up imports");
		return false;
	}
	logman.Log("imports have been set up");

	logman.Log("setting up cpuid spoof...");
	if (!SetupCpuidSpoof())
	{
		logman.Error("failed to set up cpuid spoof");
		return false;
	}
	logman.Log("cpuid has been set up");

	logman.Log("setting up hooks...");
	if (!SetupHooks())
	{
		logman.Error("failed to set up hooks");
		return false;
	}
	logman.Log("hooks have been set up");

	return true;
}

extern "C" void AsmAimwareEntryPointInvoke();

bool Aimware::Invoke()
{
	hyprutils::LogManager& logman = GetLogManager();
	hypr::SegmentMapper& mapper = GetSegmentMapper();
	uintptr_t entry_point = mapper.TranslateAddress(0x11B75003DD);

	logman.Log("calling entry point {:X}...", entry_point);

	// u can just directly use the address 0x11B75003DD
	// just because of standard
#ifdef USE_TRACER
	std::filesystem::remove("trace.txt");
	hyprtrace::ExecutionTracer::StartTracingAt(reinterpret_cast<uintptr_t>(AsmAimwareEntryPointInvoke), [](hyprutils::LogManager* logman, PCONTEXT context) -> hyprtrace::ExecutionTracer::ExecutionTraceStatus
		{
			static std::ofstream file{ "trace.txt" };
			std::println(file, "{:X}", context->Rip);
			std::println(file, "rax {:X} | rbx {:X} | rcx {:X} | rdx {:X} | rdi {:X} | rsi {:X} | r8 {:X} | r9 {:X} | r10 {:X} | r11 {:X} | r12 {:X} | r13 {:X} | r14 {:X}",
				context->Rax,
				context->Rbx,
				context->Rcx,
				context->Rdx,
				context->Rdi,
				context->Rsi,
				context->R8,
				context->R9,
				context->R10,
				context->R11,
				context->R12,
				context->R13,
				context->R14);

			if (context->Rip == 0x11B7F2B241)
			{
				MessageBoxA(NULL, "traced done, check the trace.txt", "TRACE", MB_ICONINFORMATION);
				file.flush();
				return hyprtrace::ExecutionTracer::ExecutionTraceStatus::kStopTracing;
			}
			return hyprtrace::ExecutionTracer::ExecutionTraceStatus::kContinueTracing;
		});
#else
	HANDLE thread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(AsmAimwareEntryPointInvoke), nullptr, 0, nullptr);

	if (thread)
		CloseHandle(thread);
#endif


	return true;
}

bool Aimware::AfterInvoke()
{
	return true;
}



