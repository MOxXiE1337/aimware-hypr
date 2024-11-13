#include "../aimware.h"

HANDLE FindFirstFileWHook(LPCWSTR file_name, LPWIN32_FIND_DATAW find_file_data)
{
	Aimware& aw = Aimware::GetInstance();
	std::wstring path = file_name;

	if (path.find(L"C:\\Users\\MOxXiE\\AppData\\Roaming\\PytceRauCcyu\\Xqsdqx\\") != std::wstring::npos)
	{
		path.replace(0, 52, aw.GetConfigPath());
		return FindFirstFileW(path.c_str(), find_file_data);
	}

	return FindFirstFileW(file_name, find_file_data);
}

HANDLE CreateFileWHook(LPCWSTR file_name, DWORD da, DWORD sm, LPSECURITY_ATTRIBUTES sa, DWORD cd, DWORD faa, HANDLE tf)
{
	Aimware& aw = Aimware::GetInstance();
	std::wstring path = file_name;

	if (path.find(L"C:\\Users\\MOxXiE\\AppData\\Roaming\\PytceRauCcyu\\Xqsdqx\\") != std::wstring::npos)
	{
		path.replace(0, 52, aw.GetConfigPath());
		return CreateFileW(path.c_str(), da, sm, sa, cd, faa, tf);
	}

	return CreateFileW(file_name, da, sm, sa, cd, faa, tf);
}