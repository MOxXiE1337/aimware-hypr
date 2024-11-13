#include "../aimware.h"

HINSTANCE ShellExecuteWHook(HWND hwnd, LPCWSTR operation, LPCWSTR file, LPCWSTR parameter, LPCWSTR directory, INT show_cmd)
{
	Aimware& aw = Aimware::GetInstance();

	if (!wcscmp(file, L"C:\\Users\\MOxXiE\\AppData\\Roaming\\PytceRauCcyu\\Xqsdqx\\"))
	{
		return ShellExecuteW(hwnd, operation, aw.GetConfigPath().c_str(), parameter, nullptr, show_cmd);
	}
	return ShellExecuteW(hwnd, operation, file, parameter, directory, show_cmd);
}