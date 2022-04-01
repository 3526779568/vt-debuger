EXECUTE_CONTEXT_ASM struct 1
		bitFlag byte ?;		;;�����־����Ҫ���жϵ�ǰ�������Ƿ��Ѿ���������жϵ㡣�ﵽ������ͣ����ֻ����һ���쳣�Ĺ���
		last_bit_rip qword ?;	;;�����־Ҳ����Ҫ����Ϊ��fault�����أ�����Ҫ���������־���ж��ϴ��Ƿ����ع�������������ѭ��
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
	;;;�жϵ�ǰ���̵���һ��ָʾ
	cmp debugstatus,0
	jz processloop;
	;���￪ʼ����
	;int 3
	;xchg sp,sp
	cmp debugstatus,102 ;��������
	jz step_into;
	cmp debugstatus,103;ִ�е�����
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

	;;�μĴ���
	;����CR4֧��wrfsbase/wrgsbase
	mov rax,cr4;
	bts rax,16;
	mov cr4,rax;
	mov rax,execute_context.SegDs;
	mov ds,ax;
	mov rax,execute_context.SegEs;
	mov es,ax;
	mov rax, execute_context.kGuestFsBase;	;д��fs base
	wrfsbase rax;
	;mov rax, execute_context.kGuestGsBase;  ;д��gs base
	;wrgsbase rax							;˫�����Ե�ʱ���ը
	;;mov ax,execute_context.SegFs;		;64λ��Ҫ����
	;;mov fs,ax;
	;swapgs								;����gs
	;mov rcx,0C0000102H					;IA32_KERNEL_GS_BASE
	;mov rdx,execute_context.kGuestGsBase;
	;shr rdx,32
	;mov rax,execute_context.kGuestGsBase;
	;wrmsr
	;vm-entry�Զ��л����л���ȥ����
	swapgs								;������guest gs
	;;mov ax,execute_context.SegGs;		;64λ��Ҫ����
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