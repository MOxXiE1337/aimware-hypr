#include "aimware.h"

#include <hyprtrace/api_tracer.h>

HANDLE FindFirstFileWHook(LPCWSTR, LPWIN32_FIND_DATAW);
HANDLE CreateFileWHook(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
HINSTANCE ShellExecuteWHook(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);

bool Aimware::SetupHooks()
{
	hyprutils::LogManager& logman = GetLogManager();

	if (!hyprtrace::ApiTracer::SetApiInlineHook("kernel32.dll", "FindFirstFileW", FindFirstFileWHook))
	{
		logman.Error("failed to hook kernel32.dll!FindFirstFileW");
		return false;
	}
	if (!hyprtrace::ApiTracer::SetApiInlineHook("kernel32.dll", "CreateFileW", CreateFileWHook))
	{
		logman.Error("failed to hook kernel32.dll!CreateFileW");
		return false;
	}
	if (!hyprtrace::ApiTracer::SetApiInlineHook("shell32.dll", "ShellExecuteW", ShellExecuteWHook))
	{
		logman.Error("failed to hook shell32.dll!ShellExecuteW");
		return false;
	}
	return true;
}