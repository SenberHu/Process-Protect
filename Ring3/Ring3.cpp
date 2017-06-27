#include<stdio.h>
#include<Windows.h>  

#define IOCTL1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)  

int main()
{
	HANDLE handle = CreateFileA("\\\\.\\MySSDTHookDevice_link", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		MessageBoxA(0, "打开设备失败", "错误", 0);
		return 0;
	}
	unsigned char buffer[50] = { 0 };
	DWORD len;
	DWORD MyProcessID = GetCurrentProcessId();
	_itow(MyProcessID, (wchar_t*)buffer, 10);
	if (DeviceIoControl(handle, IOCTL1, buffer, sizeof(wchar_t)*(wcslen((wchar_t*)buffer) + 1), buffer, 49, &len, NULL)) {
		printf("OK! Process is Protect");
	}
	CloseHandle(handle);
	getchar();
	return 0;
}