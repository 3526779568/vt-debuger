EXECUTE_CONTEXT_ASM struct 1
		bitFlag byte ?;		;;这个标志很重要，判断当前调试器是否已经处理过命中断点。达到类似暂停进程只处理一次异常的功能
		last_bit_rip qword ?;	;;这个标志也很重要，因为是fault类拦截，所有要根据这个标志来判断上次是否拦截过。否则陷入死循环
		thread qword ?;
		kGuestGsBase qword ?; ;;wrmsr
		kGuestFsBase qword ?;
		kKernelGsBase qword ?;
		kKernelFsBase qword ?;

		SegCs qword ?;
		SegDs qword ?;
		SegEs qword ?;
		SegFs qword ?;
		SegGs qword ?;
		SegSs qword ?;
		EFlags qword ?;

		DrZero qword ?;
		DrOne qword ?;
		DrTwo qword ?;
		DrThree qword ?;
		DrSix qword ?;
		DrSeven qword ?;

		RaxQ qword ?;
		RcxQ qword ?;
		RdxQ qword ?;
		RbxQ qword ?;
		RspQ qword ?;
		RbpQ qword ?;
		RsiQ qword ?;
		RdiQ qword ?;
		REight qword ?;
		RNight qword ?;
		RTen qword ?;
		REleven qword ?;
		RTwelve qword ?;
		RThirteen qword ?;
		RFourteen qword ?;
		RFifteen qword ?;
		Ripq qword ?;

EXECUTE_CONTEXT_ASM ends

.data
msg byte "ProcessPauseLoop";

extern execute_context:EXECUTE_CONTEXT_ASM
extern DbgPrint:Proc
extern UtilVmCall:proc
extern debugstatus:qword;

.code
public ProcessPauseLoop;
ProcessPauseLoop proc
processloop:
	;;test
	;;lea rcx,[msg]
	;;call DbgPrint;
	;;;判断当前进程的下一步指示
	cmp debugstatus,0
	jz processloop;
	;这里开始返回
	;int 3
	;xchg sp,sp
	cmp debugstatus,102 ;单步进入
	jz step_into;
	cmp debugstatus,103;执行到返回
	jz step_ret;
	jmp step_other;

step_into:
	jmp step_other;
step_ret:
	jmp step_other;
step_other:
	mov debugstatus,0 ;wait status for next


	mov rax,execute_context.DrZero;
	mov dr0,rax;
	mov rax,execute_context.DrOne;
	mov dr1,rax;
	mov rax,execute_context.DrTwo;
	mov dr2,rax;
	mov rax,execute_context.DrThree;
	mov dr3,rax;
	mov rax,execute_context.DrSix;
	mov dr6,rax;
	mov rax,execute_context.DrSeven;
	mov dr7,rax;

	;;段寄存器
	;设置CR4支持wrfsbase/wrgsbase
	mov rax,cr4;
	bts rax,16;
	mov cr4,rax;
	mov rax,execute_context.SegDs;
	mov ds,ax;
	mov rax,execute_context.SegEs;
	mov es,ax;
	mov rax, execute_context.kGuestFsBase;	;写回fs base
	wrfsbase rax;
	;mov rax, execute_context.kGuestGsBase;  ;写回gs base
	;wrgsbase rax							;双机调试的时候会炸
	;;mov ax,execute_context.SegFs;		;64位不要操作
	;;mov fs,ax;
	;swapgs								;交换gs
	;mov rcx,0C0000102H					;IA32_KERNEL_GS_BASE
	;mov rdx,execute_context.kGuestGsBase;
	;shr rdx,32
	;mov rax,execute_context.kGuestGsBase;
	;wrmsr
	;vm-entry自动切换，切换回去即可
	swapgs								;交换回guest gs
	;;mov ax,execute_context.SegGs;		;64位不要操作
	;;mov gs,ax;

	mov rcx,execute_context.RcxQ;
	mov rdx,execute_context.RdxQ;
	mov rbx,execute_context.RbxQ;
	mov rbp,execute_context.RbpQ;
	mov rsi,execute_context.RsiQ;
	mov rdi,execute_context.RdiQ;
	mov rdi,execute_context.RdiQ;
	mov r8,execute_context.REight;
	mov r9,execute_context.RNight;
	mov r10,execute_context.RTen;
	mov r11,execute_context.REleven;
	mov r12,execute_context.RTwelve;
	mov r13,execute_context.RThirteen;
	mov r14,execute_context.RFourteen;
	mov r15,execute_context.RFifteen;
	mov rax,execute_context.RaxQ;

	push execute_context.SegSs
	push execute_context.RspQ
	push execute_context.EFlags
	push execute_context.SegCs
	push execute_context.Ripq
	mov execute_context.bitFlag,0;
	mov execute_context.last_bit_rip,0;
	iretq
ProcessPauseLoop endp

end