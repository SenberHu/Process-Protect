 #include<ntifs.h>

VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DefDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IoctlDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);

//定义的ioctl控制码  
#define IOCTL1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)  

typedef struct _DEVICE_EXTENSION {
	UNICODE_STRING SymLinkName; //我们定义的设备扩展里只有一个符号链接名成员  
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

//我们将 NtOpenProcess hook 到自己的函数  
NTSTATUS NTAPI MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

//KeServiceDescriptorTable 中我们感兴趣的结构  
typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}KESERVICE_DESCRIPTOR_TABLE, *PKESERVICE_DESCRIPTOR_TABLE;

//ntoskrnl.exe (ntoskrnl.lib) 导出的 KeServiceDescriptorTable  
extern PKESERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

//关闭页面保护  
void PageProtectClose()
{
	__asm {
		cli
		mov eax, cr0
		and eax, not 10000h
		mov cr0, eax
	}
}

//启用页面保护  
void PageProtectOpen()
{
	__asm {
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
		sti
	}
}

//根据 ZwXXXX的地址 获取服务函数在 SSDT 中所对应的服务的索引号  
#define SYSTEMCALL_INDEX(ServiceFunction) (*(PULONG)((PUCHAR)ServiceFunction + 1))  

ULONG oldNtOpenProcess;//之前的NtOpenProcess  
ULONG ProtectProcessID = 0;//要保护的进程ID  

#pragma code_seg("INIT")  
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("DriverEntry\r\n");

	pDriverObject->DriverUnload = DriverUnload;//注册驱动卸载函数  

											   //注册派遣函数  
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DefDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DefDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDispatchRoutine;

	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;

	//创建设备名称的字符串  
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\MySSDTHookDevice");

	//创建设备  
	status = IoCreateDevice(pDriverObject, sizeof(DEVICE_EXTENSION), &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;//将设备设置为缓冲设备  
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;//得到设备扩展  

														  //创建符号链接  
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, L"\\??\\MySSDTHookDevice_link");
	pDevExt->SymLinkName = symLinkName;
	status = IoCreateSymbolicLink(&symLinkName, &devName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}

	//Hook SSDT  
	PageProtectClose();
	//得到原来的地址，记录在 oldNtOpenProcess  
	oldNtOpenProcess = KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(ZwOpenProcess)];
	//修改SSDT中 NtOpenProcess 的地址，使其指向 MyNtOpenProcess  
	KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(ZwOpenProcess)] = (ULONG)&MyNtOpenProcess;
	DbgPrint("Old Addr：0x%X\r\n", oldNtOpenProcess);
	PageProtectOpen();

	return STATUS_SUCCESS;
}

DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	PageProtectClose();
	//修改SSDT中 NtOpenProcess 的地址，使其指向 oldNtOpenProcess  
	//也就是在驱动卸载时恢复原来的地址  
	KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(ZwOpenProcess)] = oldNtOpenProcess;
	PageProtectOpen();

	PDEVICE_OBJECT pDevObj;
	pDevObj = pDriverObject->DeviceObject;

	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;//得到设备扩展  

																			//删除符号链接  
	UNICODE_STRING pLinkName = pDevExt->SymLinkName;
	IoDeleteSymbolicLink(&pLinkName);

	//删除设备  
	IoDeleteDevice(pDevObj);
}

NTSTATUS DefDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS IoctlDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	//得到I/O堆栈的当前这一层，也就是IO_STACK_LOCATION结构的指针  
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);

	ULONG in_size = stack->Parameters.DeviceIoControl.InputBufferLength;//得到输入缓冲区的大小  
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;//得到控制码  

	PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;//得到缓冲区指针  

	switch (code)
	{
	case IOCTL1:
		DbgPrint("Get ioctl code 1\r\n");

		//用 RtlInitUnicodeString 将用户发送的 wchar_t* 封装成 UNICODE_STRING  
		UNICODE_STRING temp;
		RtlInitUnicodeString(&temp, (PWSTR)buffer);
		//转换成 Unsigned Long 类型，这就是我们要保护的进程  
		RtlUnicodeStringToInteger(&temp, 0, &ProtectProcessID);
		DbgPrint("ProtectProcessID: %u\r\n", ProtectProcessID);
		break;
	default:
		status = STATUS_INVALID_VARIANT;
		//如果是没有处理的IRP，则返回STATUS_INVALID_VARIANT，这意味着用户模式的I/O函数失败，但并不会设置GetLastError  
	}

	// 完成IRP  
	pIrp->IoStatus.Status = status;//设置IRP完成状态，会设置用户模式下的GetLastError  
	pIrp->IoStatus.Information = 0;//设置操作的字节  
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);//完成IRP，不增加优先级  
	return status;
}

NTSTATUS NTAPI MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	//判断要打开的进程ID是不是我们要保护的进程  
	if (ClientId->UniqueProcess == (HANDLE)ProtectProcessID)
		return (NTSTATUS)-1073741790;//返回“拒绝访问”错误  
									 //不是我们要保护的进程，定义一个函数指针 _NtOpenProcess ,根据 oldNtOpenProcess 记录的真实函数的地址进行 Call  
									 //也就是说其他进程直接交还给系统的 NtOpenProcess 处理  
	typedef NTSTATUS(NTAPI * _NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	_NtOpenProcess _oldNtOpenProcess = (_NtOpenProcess)oldNtOpenProcess;
	return _oldNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}