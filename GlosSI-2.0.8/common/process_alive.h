#pragma once
#include <Windows.h>
#include <appmodel.h>
#include <tlhelp32.h>
#include <algorithm>
#include <vector>

namespace process_alive
{
	inline std::wstring GetProcessPackageFamilyName(DWORD pid)
	{
		const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (process == nullptr)
			return {};

		UINT32 length = 0;
		LONG result = ::GetPackageFamilyName(process, &length, nullptr);
		if (result != ERROR_INSUFFICIENT_BUFFER || length == 0)
		{
			CloseHandle(process);
			return {};
		}

		std::wstring familyName(length, L'\0');
		result = ::GetPackageFamilyName(process, &length, &familyName[0]);
		CloseHandle(process);
		if (result != ERROR_SUCCESS)
			return {};

		familyName.resize(length - 1);
		return familyName;
	}

	//stolen from: https://stackoverflow.com/questions/1591342/c-how-to-determine-if-a-windows-process-is-running
	inline bool IsProcessRunning(const wchar_t *processName)
	{
		bool exists = false;
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry))
			do {
				if (!_wcsicmp(entry.szExeFile, processName))
				{
					exists = true;
					break;
				}
			} while (Process32Next(snapshot, &entry));

			CloseHandle(snapshot);
			return exists;
	}

	inline BOOL IsProcessRunning(DWORD pid)
	{
		const HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
		if (process == nullptr)
			return false;
		const DWORD ret = WaitForSingleObject(process, 0);
		CloseHandle(process);
		return ret == WAIT_TIMEOUT;
	}

	inline void AddChildProcesses(std::vector<DWORD>& processIds)
	{
		const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return;

		std::vector<PROCESSENTRY32> processes;
		PROCESSENTRY32 entry{};
		entry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &entry))
		{
			do
			{
				processes.push_back(entry);
			} while (Process32Next(snapshot, &entry));
		}
		CloseHandle(snapshot);

		bool foundChild;
		do
		{
			foundChild = false;
			for (const auto& process : processes)
			{
				if (process.th32ProcessID != 0 &&
					std::find(processIds.begin(), processIds.end(), process.th32ProcessID) == processIds.end() &&
					std::find(processIds.begin(), processIds.end(), process.th32ParentProcessID) != processIds.end())
				{
					processIds.push_back(process.th32ProcessID);
					foundChild = true;
				}
			}
		} while (foundChild);
	}

	inline void AddPackageProcesses(const std::wstring& packageFamilyName, std::vector<DWORD>& processIds)
	{
		if (packageFamilyName.empty())
			return;

		const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return;

		PROCESSENTRY32 entry{};
		entry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &entry))
		{
			do
			{
				if (entry.th32ProcessID != 0 &&
					std::find(processIds.begin(), processIds.end(), entry.th32ProcessID) == processIds.end() &&
					GetProcessPackageFamilyName(entry.th32ProcessID) == packageFamilyName)
				{
					processIds.push_back(entry.th32ProcessID);
				}
			} while (Process32Next(snapshot, &entry));
		}
		CloseHandle(snapshot);
	}
}