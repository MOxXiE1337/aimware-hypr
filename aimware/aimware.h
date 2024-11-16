#pragma once
#include <filesystem>
#include <hypr/loader.h>
#include <hyprutils/singleton.h>

struct dr7 {
	uint32_t L0 : 1;
	uint32_t G0 : 1;
	uint32_t L1 : 1;
	uint32_t G1 : 1;
	uint32_t L2 : 1;
	uint32_t G2 : 1;
	uint32_t L3 : 1;
	uint32_t G3 : 1;

	uint32_t LE : 1;
	uint32_t GE : 1;
	uint32_t no_use1 : 1;
	uint32_t RTM : 1;
	uint32_t no_use2 : 1;
	uint32_t GD : 1;
	uint32_t no_use3 : 2;

	uint32_t RW0 : 2;
	uint32_t LEN0 : 2;
	uint32_t RW1 : 2;
	uint32_t LEN1 : 2;
	uint32_t RW2 : 2;
	uint32_t LEN2 : 2;
	uint32_t RW3 : 2;
	uint32_t LEN3 : 2;
};

class Aimware : public hypr::Loader, public hyprutils::Singleton<Aimware>
{
private:
	std::string appdata_path_;
	std::wstring cfg_path_;

	static LONG NTAPI ExceptionHandler(struct _EXCEPTION_POINTERS* exception);
	static LONG NTAPI OsVersionSpoofExceptionHandler(struct _EXCEPTION_POINTERS* exception);
public:
	Aimware() : Loader("Aimware"), appdata_path_(std::getenv("APPDATA"))
	{
	
	}

	std::wstring GetConfigPath() { return cfg_path_; }

	bool PrevMap();
	bool PrevInvoke();
	bool Invoke();
	bool AfterInvoke();

	bool SetupImports();
	bool SetupOSVersionSpoof();
	bool SetupCpuidSpoof();
	bool SetupHooks();
};
