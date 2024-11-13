#pragma once
#include <filesystem>
#include <hypr/loader.h>
#include <hyprutils/singleton.h>

class Aimware : public hypr::Loader, public hyprutils::Singleton<Aimware>
{
private:
	std::string appdata_path_;
	std::wstring cfg_path_;
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
	bool SetupCpuidSpoof();
	bool SetupHooks();
};
