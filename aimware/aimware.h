#pragma once
#include <hypr/loader.h>
#include <hyprutils/singleton.h>

class Aimware : public hypr::Loader, public hyprutils::Singleton<Aimware>
{
private:
	const std::string appdata_path_;
public:
	Aimware() : Loader("Aimware"), appdata_path_(std::getenv("APPDATA"))
	{
	}

	bool PrevMap();
	bool PrevInvoke();
	bool Invoke();
	bool AfterInvoke();

	bool SetupImports();
	bool SetupCpuidSpoof();
};
