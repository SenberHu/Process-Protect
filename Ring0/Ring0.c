 #include<ntifs.h>

VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DefDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IoctlDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);

//�����ioctl������  
#define IOCTL1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)  

typedef struct _DEVICE_EXTENSION {
	UNICODE_STRING SymLinkName; //���Ƕ�����豸��չ��ֻ��һ��������������Ա  
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

//���ǽ� NtOpenProcess hook ���Լ��ĺ���  
NTSTATUS NTAPI MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

//KeServiceDescriptorTable �����Ǹ���Ȥ�Ľṹ  
typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}KESERVICE_DESCRIPTOR_TABLE, *PKESERVICE_DESCRIPTOR_TABLE;

//ntoskrnl.exe (ntoskrnl.lib) ������ KeServiceDescriptorTable  
extern PKESERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

//�ر�ҳ�汣��  
void PageProtectClose()
{
	__asm {
		cli
		mov eax, cr0
		and eax, not 10000h
		mov cr0, eax
	}
}

//����ҳ�汣��  
void PageProtectOpen()
{
	__asm {
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
		sti
	}
}

//���� ZwXXXX�ĵ�ַ ��ȡ�������� SSDT ������Ӧ�ķ����������  
#define SYSTEMCALL_INDEX(ServiceFunction) (*(PULONG)((PUCHAR)ServiceFunction + 1))  

ULONG oldNtOpenProcess;//֮ǰ��NtOpenProcess  
ULONG ProtectProcessID = 0;//Ҫ�����Ľ���ID  

#pragma code_seg("INIT")  
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("DriverEntry\r\n");

	pDriverObject->DriverUnload = DriverUnload;//ע������ж�غ���  

											   //ע����ǲ����  
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DefDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DefDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDispatchRoutine;

	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;

	//�����豸���Ƶ��ַ���  
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\MySSDTHookDevice");

	//�����豸  
	status = IoCreateDevice(pDriverObject, sizeof(DEVICE_EXTENSION), &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;//���豸����Ϊ�����豸  
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;//�õ��豸��չ  

														  //������������  
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
	//�õ�ԭ���ĵ�ַ����¼�� oldNtOpenProcess  
	oldNtOpenProcess = KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(ZwOpenProcess)];
	//�޸�SSDT�� NtOpenProcess �ĵ�ַ��ʹ��ָ�� MyNtOpenProcess  
	KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(ZwOpenProcess)] = (ULONG)&MyNtOpenProcess;
	DbgPrint("Old Addr��0x%X\r\n", oldNtOpenProcess);
	PageProtectOpen();

	return STATUS_SUCCESS;
}

DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	PageProtectClose();
	//�޸�SSDT�� NtOpenProcess �ĵ�ַ��ʹ��ָ�� oldNtOpenProcess  
	//Ҳ����������ж��ʱ�ָ�ԭ���ĵ�ַ  
	KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(ZwOpenProcess)] = oldNtOpenProcess;
	PageProtectOpen();

	PDEVICE_OBJECT pDevObj;
	pDevObj = pDriverObject->DeviceObject;

	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;//�õ��豸��չ  

																			//ɾ����������  
	UNICODE_STRING pLinkName = pDevExt->SymLinkName;
	IoDeleteSymbolicLink(&pLinkName);

	//ɾ���豸  
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

	//�õ�I/O��ջ�ĵ�ǰ��һ�㣬Ҳ����IO_STACK_LOCATION�ṹ��ָ��  
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);

	ULONG in_size = stack->Parameters.DeviceIoControl.InputBufferLength;//�õ����뻺�����Ĵ�С  
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;//�õ�������  

	PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;//�õ�������ָ��  

	switch (code)
	{
	case IOCTL1:
		DbgPrint("Get ioctl code 1\r\n");

		//�� RtlInitUnicodeString ���û����͵� wchar_t* ��װ�� UNICODE_STRING  
		UNICODE_STRING temp;
		RtlInitUnicodeString(&temp, (PWSTR)buffer);
		//ת���� Unsigned Long ���ͣ����������Ҫ�����Ľ���  
		RtlUnicodeStringToInteger(&temp, 0, &ProtectProcessID);
		DbgPrint("ProtectProcessID: %u\r\n", ProtectProcessID);
		break;
	default:
		status = STATUS_INVALID_VARIANT;
		//�����û�д����IRP���򷵻�STATUS_INVALID_VARIANT������ζ���û�ģʽ��I/O����ʧ�ܣ�������������GetLastError  
	}

	// ���IRP  
	pIrp->IoStatus.Status = status;//����IRP���״̬���������û�ģʽ�µ�GetLastError  
	pIrp->IoStatus.Information = 0;//���ò������ֽ�  
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);//���IRP�����������ȼ�  
	return status;
}

NTSTATUS NTAPI MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	//�ж�Ҫ�򿪵Ľ���ID�ǲ�������Ҫ�����Ľ���  
	if (ClientId->UniqueProcess == (HANDLE)ProtectProcessID)
		return (NTSTATUS)-1073741790;//���ء��ܾ����ʡ�����  
									 //��������Ҫ�����Ľ��̣�����һ������ָ�� _NtOpenProcess ,���� oldNtOpenProcess ��¼����ʵ�����ĵ�ַ���� Call  
									 //Ҳ����˵��������ֱ�ӽ�����ϵͳ�� NtOpenProcess ����  
	typedef NTSTATUS(NTAPI * _NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	_NtOpenProcess _oldNtOpenProcess = (_NtOpenProcess)oldNtOpenProcess;
	return _oldNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}