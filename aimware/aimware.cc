
#include "aimware.h"
#include "data/aimware_hdmp.h"
#include "data/aimware_hseg.h"

#include "zydis/Zydis.h"

#include <hyprtrace/api_tracer.h>
#include <hyprtrace/exec_tracer.h>

LONG NTAPI Aimware::ExceptionHandler(struct _EXCEPTION_POINTERS* exception)
{
	uint32_t code = exception->ExceptionRecord->ExceptionCode;

	if (code == DBG_PRINTEXCEPTION_C || code == DBG_PRINTEXCEPTION_WIDE_C)
		return EXCEPTION_CONTINUE_SEARCH;

	MessageBoxA(NULL, std::format("exception {:X} not handled at {:X}", exception->ExceptionRecord->ExceptionCode, reinterpret_cast<uintptr_t>(exception->ExceptionRecord->ExceptionAddress)).c_str(), "Aimware Error", MB_ICONERROR);
	return EXCEPTION_CONTINUE_SEARCH;
}

bool Aimware::PrevMap()
{
	hyprutils::LogManager& logman = GetLogManager();
	hypr::RuntimeDump&     dump = GetRuntimeDump();
	hypr::SegmentMapper&   mapper = GetSegmentMapper();

	//AddVectoredExceptionHandler(0, ExceptionHandler);

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

	hyprtrace::ApiTracer::AddFilteringModule("msvcrt.dll");

	logman.Log("setting up imports...");
	if (!SetupImports())
	{
		logman.Error("failed to set up imports");
		return false;
	}
	logman.Log("imports have been set up");

	logman.Log("setting up os version spoof...");
	if (!SetupOSVersionSpoof())
	{
		logman.Error("failed to set up os version spoof");
		return false;
	}
	logman.Log("os version spoof has been set up");

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

#ifdef USE_TRACER
ZydisDecodedInstruction insn;
ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
ZydisDecoder decoder;
ZydisFormatter formatter;
#endif

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


	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);

	hyprtrace::ExecutionTracer::StartTracingAt(reinterpret_cast<uintptr_t>(AsmAimwareEntryPointInvoke), [](hyprutils::LogManager* logman, PCONTEXT context) -> hyprtrace::ExecutionTracer::ExecutionTraceStatus
		{
			char buffer[256] = { 0 };
			static std::ofstream file{ "trace.txt" };

			ZydisDecoderDecodeFull(&decoder, reinterpret_cast<void*>(context->Rip), 0x11B770BA13 - context->Rip, &insn, operands);
			ZydisFormatterFormatInstruction(&formatter, &insn, operands, insn.operand_count_visible, buffer, sizeof(buffer), context->Rip, ZYAN_NULL);

			std::println(file, "{:X} {}", context->Rip, buffer);
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

			if (context->Rip == 0x11B770BA13)
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



