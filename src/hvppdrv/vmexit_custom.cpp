#include "vmexit_custom.h"
#include <hvpp/lib/cr3_guard.h>
#include <hvpp/lib/mp.h>
#include <hvpp/lib/log.h>
#include "SsdtHook.h"
#include "MemoryHide.h"
#include "DbgApi.h"
#include "NoTraceBP.h"
#include "hvpp/ia32/cpuid/cpuid_eax_01.h"


extern  MemoryHide hide;
extern  SSDTHook* ssdthook;
extern ddy::DbgkKernel dbgkapi;
extern NoTraceBP infbp;
extern InfEvent infevent;
extern set<PEPROCESS> AttachPreocess;
extern map<PETHREAD, CONTEXT> threadcontext;
pa_t last_mtf[100] = { 0 };
ULONG64 last_rip[100] = { 0 };
vmx::io_bitmap_t io_bitmap{ 0 };

auto vmexit_custom_handler::setup(vcpu_t& vp) noexcept -> error_code_t
{
	base_type::setup(vp);

	//
	// Set per-VCPU data and mirror current physical memory in EPT.
	//
	auto data = new per_vcpu_data{};
	data->ept.map_identity();
	data->page_exec = 0;
	data->page_read = 0;
	vp.user_data(data);

	//
	// Enable EPT.
	//
	vp.ept(data->ept);

	vp.ept_enable();

#if 1
	//
	// Enable exitting on 0x64 I/O port (keyboard).
	//
	//这里关闭I/O指令 太卡了
	auto procbased_ctls = vp.processor_based_controls();
	procbased_ctls.use_io_bitmaps = true;
	vp.processor_based_controls(procbased_ctls);

	//开启无限模式
	auto procsecond = vp.processor_based_controls2();
	procsecond.unrestricted_guest = true;
	vp.processor_based_controls2(procsecond);

	//bitmap<>(io_bitmap.a).set(0x64);
	vp.io_bitmap(io_bitmap);

	//trap cpuid异常
	msr::vmx_entry_ctls_t entry_ctls = vp.vm_entry_controls();
	entry_ctls.load_debug_controls = true;
	vp.vm_entry_controls(entry_ctls);

	msr::vmx_exit_ctls_t exit_ctls = vp.vm_exit_controls();
	exit_ctls.acknowledge_interrupt_on_exit = true;
	exit_ctls.save_debug_controls = true;
	vp.vm_exit_controls(exit_ctls);
#else
	//
	// Turn on VM-exit on everything we support.
	//

	auto procbased_ctls = vp.processor_based_controls();

	//
	// Since VMWare handles rdtsc(p) instructions by its own
	// magical way, we'll disable our own handling.  Setting
	// this in VMWare makes the guest OS completely bananas.
	//
	// procbased_ctls.rdtsc_exiting = true;

	//
	// Use either "use_io_bitmaps" or "unconditional_io_exiting",
	// try to avoid using both of them.
	//

// #define USE_IO_BITMAPS
// #define DISABLE_GP_EXITING

#ifdef USE_IO_BITMAPS
	procbased_ctls.use_io_bitmaps = true;
#else
	procbased_ctls.unconditional_io_exiting = true;
#endif
	procbased_ctls.mov_dr_exiting = true;
	procbased_ctls.cr3_load_exiting = true;
	procbased_ctls.cr3_store_exiting = true;
	procbased_ctls.invlpg_exiting = true;
	vp.processor_based_controls(procbased_ctls);

	auto procbased_ctls2 = vp.processor_based_controls2();
	procbased_ctls2.descriptor_table_exiting = true;
	vp.processor_based_controls2(procbased_ctls2);

	vmx::msr_bitmap_t msr_bitmap{};
	memset(msr_bitmap.data, 0xff, sizeof(msr_bitmap));
	vp.msr_bitmap(msr_bitmap);

#ifdef USE_IO_BITMAPS
	vmx::io_bitmap_t io_bitmap{};
	memset(io_bitmap.data, 0xff, sizeof(io_bitmap));

	//
	// Disable VMWare backdoor.
	//
	bitmap<>(io_bitmap.a).clear(0x5658);
	bitmap<>(io_bitmap.a).clear(0x5659);

	vp.io_bitmap(io_bitmap);
#endif

#ifdef DISABLE_GP_EXITING
	//
	// Catch all exceptions except #GP.
	//
	vmx::exception_bitmap_t exception_bitmap{ ~0ul };
	exception_bitmap.general_protection = false;
	vp.exception_bitmap(exception_bitmap);
#else
	//
	// Catch all exceptions.
	//
	vp.exception_bitmap(vmx::exception_bitmap_t{ ~0ul });
#endif

	//
	// VM-execution control fields include guest/host masks
	// and read shadows for the CR0 and CR4 registers.
	// These fields control executions of instructions that
	// access those registers (including CLTS, LMSW, MOV CR,
	// and SMSW).
	// They are 64 bits on processors that support Intel 64
	// architecture and 32 bits on processors that do not.
	//
	// In general, bits set to 1 in a guest/host mask correspond
	// to bits "owned" by the host:
	//   - Guest attempts to set them (using CLTS, LMSW, or
	//     MOV to CR) to values differing from the corresponding
	//     bits in the corresponding read shadow cause VM exits.
	//   - Guest reads (using MOV from CR or SMSW) return values
	//     for these bits from the corresponding read shadow.
	//
	// Bits cleared to 0 correspond to bits "owned" by the
	// guest; guest attempts to modify them succeed and guest
	// reads return values for these bits from the control
	// register itself.
	// (ref: Vol3C[24.6.6(Guest/Host Masks and Read Shadows for CR0 and CR4)])
	//
	// TL;DR:
	//   When bit in guest/host mask is set, write to the control
	//   register causes VM-exit.  Mov FROM CR0 and CR4 returns
	//   values in the shadow register values.
	//
	// Note that SHADOW register value and REAL register value may
	// differ.  The guest will behave according to the REAL control
	// register value.  Only read from that register will return the
	// fake (aka "shadow") value.
	//

	vp.cr0_guest_host_mask(cr0_t{ ~0ull });
	vp.cr4_guest_host_mask(cr4_t{ ~0ull });
#endif

	return {};
}

void vmexit_custom_handler::teardown(vcpu_t& vp) noexcept
{
	auto& data = user_data(vp);
	delete& data;

	vp.user_data(nullptr);
}

void vmexit_custom_handler::handle_execute_cpuid(vcpu_t& vp) noexcept
{
	if (vp.context().eax == 1)//这个是vmx启动标志
	{
		cpuid_eax_01 cpuid_info;
		ia32_asm_cpuid(cpuid_info.cpu_info, 1);
		vp.context().rax = cpuid_info.eax;
		vp.context().rbx = cpuid_info.ebx;
		cpuid_info.feature_information_ecx.hypervisor_present = 0;
		cpuid_info.feature_information_ecx.virtual_machine_extensions = 0;
		vp.context().rcx = cpuid_info.ecx;
		vp.context().rdx = cpuid_info.edx;
	}
	else
	{
		base_type::handle_execute_cpuid(vp);
	}
}

void vmexit_custom_handler::handle_execute_vmcall(vcpu_t& vp) noexcept
{
	auto& data = user_data(vp);
	switch (vp.context().rcx)
	{
	case VMCALLVALUE::DDYMemoryHide:
	{
		auto data = static_cast<HookData*>((PVOID)vp.context().rdx);
		auto guestpa1 = pa_t::from_va(data->rw_page_va);
		auto guestpa2 = pa_t::from_va(data->e_page_va);
		vp.ept().split_2mb_to_4kb(guestpa1 & ept_pd_t::mask, guestpa1 & ept_pd_t::mask);
		vp.ept().split_2mb_to_4kb(guestpa2 & ept_pd_t::mask, guestpa2 & ept_pd_t::mask);
		vp.ept().map_4kb(guestpa1, guestpa2, epte_t::access_type::execute);
		vmx::invept_single_context(vp.ept().ept_pointer());
		break;
	}
	case VMCALLVALUE::DDYRemoveMemoryHide:
	{
		auto data = static_cast<HookData*>((PVOID)vp.context().rdx);
		auto guestpa1 = pa_t::from_va(data->rw_page_va);
		pa_t pa{ (ULONG64)data->rw_page_pa };
		if (guestpa1.value() == 0)
		{
			guestpa1 = pa;
		}
		auto guestpa2 = pa_t::from_va(data->e_page_va);
		vp.ept().map_4kb(guestpa1, guestpa1, epte_t::access_type::read_write_execute);
		vmx::invept_single_context(vp.ept().ept_pointer());
		break;
	}
	case VMCALLVALUE::DDYInfHook:
	{
		if (infbp.pagemonitor.locked)
		{
			pa_t guestpa{ (ULONG64)infbp.pagemonitor.page_pa };
			vp.ept().split_2mb_to_4kb(guestpa & ept_pd_t::mask, guestpa & ept_pd_t::mask);
			vp.ept().map_4kb(guestpa, guestpa, epte_t::access_type::none);//读写执行断点
		}
		vmx::invept_single_context(vp.ept().ept_pointer());
		break;
	}
	case VMCALLVALUE::DDYInfUnHook:
	{
		if (infbp.pagemonitor.locked)
		{
			pa_t guestpa{ (ULONG64)infbp.pagemonitor.page_pa };
			vp.ept().map_4kb(guestpa, guestpa, epte_t::access_type::read_write_execute);//恢复所有页面权限
		}
		vmx::invept_single_context(vp.ept().ept_pointer());
		break;
	}
	default:
		base_type::handle_execute_vmcall(vp);
		return;
	}
}


void vmexit_custom_handler::handle_monitor_trap_flag(vcpu_t& vp) noexcept
{
	auto pa = last_mtf[KeGetCurrentProcessorNumber()];
	vp.ept().map_4kb(pa, pa, ia32::epte_t::access_type::none);
	auto ctr = vp.processor_based_controls();
	ctr.monitor_trap_flag = false;
	vp.processor_based_controls(ctr);
	vmx::invept_single_context(vp.ept().ept_pointer());
	vp.suppress_rip_adjust();
}

void vmexit_custom_handler::handle_mov_cr(vcpu_t& vp) noexcept
{
	base_type::handle_mov_cr(vp);
}

void vmexit_custom_handler::handle_mov_dr(vcpu_t& vp) noexcept
{
	base_type::handle_mov_dr(vp);
}

void vmexit_custom_handler::handle_gdtr_idtr_access(vcpu_t& vp) noexcept
{
	base_type::handle_gdtr_idtr_access(vp);
}

void vmexit_custom_handler::handle_ldtr_tr_access(vcpu_t& vp) noexcept
{
	base_type::handle_ldtr_tr_access(vp);
}

void vmexit_custom_handler::handle_execute_invpcid(vcpu_t& vp) noexcept
{

	base_type::handle_execute_invpcid(vp);
}

void vmexit_custom_handler::handle_execute_rdtsc(vcpu_t& vp) noexcept
{

	base_type::handle_execute_rdtsc(vp);
}

void vmexit_custom_handler::handle_execute_rdtscp(vcpu_t& vp) noexcept
{

	base_type::handle_emulate_rdtscp(vp);
}

void vmexit_custom_handler::handle_execute_wbinvd(vcpu_t& vp) noexcept
{

	base_type::handle_execute_wbinvd(vp);
}

void vmexit_custom_handler::handle_execute_xsetbv(vcpu_t& vp) noexcept
{

	base_type::handle_execute_xsetbv(vp);
}

void vmexit_custom_handler::handle_execute_rdmsr(vcpu_t& vp) noexcept
{
	base_type::handle_execute_rdmsr(vp);
}

void vmexit_custom_handler::handle_execute_wrmsr(vcpu_t& vp) noexcept
{
	base_type::handle_execute_wrmsr(vp);
}

void vmexit_custom_handler::handle_execute_io_instruction(vcpu_t& vp) noexcept
{
	base_type::handle_execute_io_instruction(vp);
}

void vmexit_custom_handler::handle_execute_invd(vcpu_t& vp) noexcept
{
	base_type::handle_execute_invd(vp);
}

void vmexit_custom_handler::handle_execute_invlpg(vcpu_t& vp) noexcept
{
	base_type::handle_execute_invlpg(vp);
}

void vmexit_custom_handler::handle_execute_vmclear(vcpu_t& vp) noexcept
{
	base_type::handle_execute_vmclear(vp);
}

void vmexit_custom_handler::handle_execute_vmlaunch(vcpu_t& vp) noexcept
{
	base_type::handle_execute_vmlaunch(vp);
}

void vmexit_custom_handler::handle_execute_vmptrld(vcpu_t& vp) noexcept
{
	base_type::handle_execute_vmptrld(vp);
}

void vmexit_custom_handler::handle_execute_vmptrst(vcpu_t& vp) noexcept
{
	base_type::handle_execute_vmptrst(vp);
}

void vmexit_custom_handler::handle_execute_vmread(vcpu_t& vp) noexcept
{
	base_type::handle_execute_vmread(vp);
}

void vmexit_custom_handler::handle_execute_vmresume(vcpu_t& vp) noexcept
{
	base_type::handle_execute_vmresume(vp);
}

void vmexit_custom_handler::handle_execute_vmwrite(vcpu_t& vp) noexcept
{
	base_type::handle_execute_vmwrite(vp);
}

void vmexit_custom_handler::handle_execute_vmxoff(vcpu_t& vp) noexcept
{
	base_type::handle_execute_vmxoff(vp);
}

void vmexit_custom_handler::handle_execute_vmxon(vcpu_t& vp) noexcept
{
	base_type::handle_execute_vmxon(vp);
}

void vmexit_custom_handler::handle_execute_invept(vcpu_t& vp) noexcept
{

	base_type::handle_execute_invept(vp);
}

void vmexit_custom_handler::handle_execute_invvpid(vcpu_t& vp) noexcept
{
	base_type::handle_execute_invvpid(vp);
}






void vmexit_custom_handler::handle_ept_violation(vcpu_t& vp) noexcept
{
	auto exit_qualification = vp.exit_qualification().ept_violation;
	auto guest_pa = vp.exit_guest_physical_address();
	auto guest_va = vp.exit_guest_linear_address();

	if (exit_qualification.data_read || exit_qualification.data_write)
	{
		//
		// Someone requested read or write access to the guest_pa,
		// but the page has execute-only access.  Map the page with
		// the "data.page_read" we've saved before in the VMCALL
		// handler and set the access to RW.
		//
		//hvpp_trace("data_read LA: 0x%p PA: 0x%p", guest_va.value(), guest_pa.value());
		if (hide.memoryhide.count(PAGE_ALIGN(guest_va.value())))
		{
			auto data = hide.memoryhide[PAGE_ALIGN(guest_va.value())];
			auto pa_rw = pa_t::from_va(data->rw_page_va);
			auto pa_e = pa_t::from_va(data->e_page_va);
			vp.ept().map_4kb(guest_pa, pa_rw, epte_t::access_type::read_write);
		}
		else//INF HOOK
		{
			CreateDebugException(vp, guest_pa, guest_va, false);
		}
	}
	else if (exit_qualification.data_execute)
	{
		//
		// Someone requested execute access to the guest_pa, but
		// the page has only read-write access.  Map the page with
		// the "data.page_execute" we've saved before in the VMCALL
		// handler and set the access to execute-only.
		//
		//hvpp_trace("data_execute LA: 0x%p PA: 0x%p", guest_va.value(), guest_pa.value());
		if (hide.memoryhide.count(PAGE_ALIGN(guest_va.value())))
		{
			auto data = hide.memoryhide[PAGE_ALIGN(guest_va.value())];
			auto pa_rw = pa_t::from_va(data->rw_page_va);
			auto pa_e = pa_t::from_va(data->e_page_va);
			vp.ept().map_4kb(guest_pa, pa_e, epte_t::access_type::execute);
		}
		else
		{
			CreateDebugException(vp, guest_pa, guest_va, true);
			//刷新缓存
			vmx::invept_single_context(vp.ept().ept_pointer());
		}
	}

	//vmx::invept_single_context(vp.ept().ept_pointer());
	//
	// An EPT violation invalidates any guest-physical mappings
	// (associated with the current EP4TA) that would be used to
	// translate the guest-physical address that caused the EPT
	// violation.  If that guest-physical address was the translation
	// of a linear address, the EPT violation also invalidates
	// any combined mappings for that linear address associated
	// with the current PCID, the current VPID and the current EP4TA.
	// (ref: Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)])
	//
	//
	// TL;DR:
	//   We don't need to call INVEPT (nor INVVPID) here, because
	//   CPU invalidates mappings for the accessed linear address
	//   for us.
	//
	//   Note1:
	//     In the paragraph above, "EP4TA" is the value of bits
	//     51:12 of EPTP.  These 40 bits contain the address of
	//     the EPT-PML4-table (the notation EP4TA refers to those
	//     40 bits).
	//
	//   Note2:
	//     If we would change any other EPT structure, INVEPT or
	//     INVVPID might be needed.
	//

	//
	// Make the instruction which fetched the memory to be executed
	// again (this time without EPT violation).
	//
	vp.suppress_rip_adjust();
}

void CreateDebugException(hvpp::vcpu_t& vp, const ia32::pa_t& guest_pa, ia32::va_t& guest_va, bool excute)
{
	//无论是否是断点的页面，都需要恢复页面权限
	vp.ept().map_4kb(guest_pa, guest_pa, epte_t::access_type::read_write_execute);
	last_mtf[KeGetCurrentProcessorNumber()] = guest_pa;
	auto ctr = vp.processor_based_controls();
	ctr.monitor_trap_flag = true;
	vp.processor_based_controls(ctr);

	PageMonitor pm;
	BreakPoint bp;
	pm.eprocess = PsGetCurrentProcess();
	pm.page_va = PAGE_ALIGN(guest_va.value());
	if (excute)
	{
		bp.address = vp.context().rip;
	}
	else
	{
		bp.address = guest_va.value();
	}
	bp.size = 8;
	if (AttachPreocess.count(pm.eprocess))//只有被调试进程才注入异常
	{
		if (!excute)
		{
			if (!infbp.IsBpInCurrentBp(bp))
			{
				return;
			}
			if (vp.guest_ss().access.descriptor_privilege_level != 3)//只有R3且没有执行过的RIP才注入异常
			{
				return;
			}
		}
		else
		{
			if (infbp.current_bp.address != bp.address)
			{
				return;
			}
		}
		if (infevent.last_lock.count(pm.eprocess))//如果没有锁住
		{
			if (!infevent.last_lock[pm.eprocess])
			{
				if (last_rip[KeGetCurrentProcessorNumber()] != vp.context().rip)//别重复执行
				{
					infevent.last_lock[pm.eprocess] = true;
					infevent.debugevent[pm.eprocess]->dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
					infevent.debugevent[pm.eprocess]->dwProcessId = (DWORD)PsGetCurrentProcessId();
					infevent.debugevent[pm.eprocess]->dwThreadId = (DWORD)PsGetCurrentThreadId();
					infevent.debugevent[pm.eprocess]->u.Exception.dwFirstChance = true;
					infevent.debugevent[pm.eprocess]->u.Exception.ExceptionRecord.ExceptionAddress = (PVOID)bp.address;
					infevent.debugevent[pm.eprocess]->u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_SINGLE_STEP;
					infevent.debugevent[pm.eprocess]->u.Exception.ExceptionRecord.ExceptionInformation[8] = 8;
					infevent.debugevent[pm.eprocess]->u.Exception.ExceptionRecord.ExceptionRecord = 0;
					infevent.debugevent[pm.eprocess]->u.Exception.ExceptionRecord.NumberParameters = 0;
					infevent.debugevent[pm.eprocess]->u.Exception.ExceptionRecord.ExceptionFlags = 0;
					last_rip[KeGetCurrentProcessorNumber()] = vp.context().rip;
					//采集线程上下文
					auto pth = PsGetCurrentThread();
					threadcontext[pth] = { 0 };
					threadcontext[pth].Dr0 = __readdr(0);
					threadcontext[pth].Dr1 = __readdr(1);
					threadcontext[pth].Dr2 = __readdr(2);
					threadcontext[pth].Dr3 = __readdr(3);
					threadcontext[pth].Dr6 = __readdr(6);
					threadcontext[pth].Dr7 = vp.guest_dr7().flags;
					threadcontext[pth].DebugControl = vp.guest_debugctl().flags;
					threadcontext[pth].EFlags = vp.context().rflags.flags;
					threadcontext[pth].R10 = vp.context().r10;
					threadcontext[pth].R11 = vp.context().r11;
					threadcontext[pth].R12 = vp.context().r12;
					threadcontext[pth].R13 = vp.context().r13;
					threadcontext[pth].R14 = vp.context().r14;
					threadcontext[pth].R15 = vp.context().r15;
					threadcontext[pth].R8 = vp.context().r8;
					threadcontext[pth].R9 = vp.context().r9;
					threadcontext[pth].Rax = vp.context().rax;
					threadcontext[pth].Rbp = vp.context().rbp;
					threadcontext[pth].Rbx = vp.context().rbx;
					threadcontext[pth].Rcx = vp.context().rcx;
					threadcontext[pth].Rdi = vp.context().rdi;
					threadcontext[pth].Rdx = vp.context().rdx;
					threadcontext[pth].Rip = vp.context().rip;
					threadcontext[pth].Rsi = vp.context().rsi;
					threadcontext[pth].Rsp = vp.context().rsp;
					threadcontext[pth].SegCs = vp.guest_cs().selector.flags;
					threadcontext[pth].SegDs = vp.guest_ds().selector.flags;
					threadcontext[pth].SegEs = vp.guest_es().selector.flags;
					threadcontext[pth].SegFs = vp.guest_fs().selector.flags;
					threadcontext[pth].SegGs = vp.guest_gs().selector.flags;
					threadcontext[pth].SegSs = vp.guest_ss().selector.flags;
					//通知调试器
					infevent.last_inf[pm.eprocess] = true;
					//解锁
					infevent.last_lock[pm.eprocess] = false;
					vp.interrupt_inject(interrupt::debug);//注入调试异常
				}
				else
				{
					last_rip[KeGetCurrentProcessorNumber()] = 0;
				}
			}
		}
	}
}

void vmexit_custom_handler::handle_exception_or_nmi(vcpu_t& vp) noexcept
{
	const auto interrupt = vp.interrupt_info();
	if (interrupt.type() == vmx::interrupt_type::hardware_exception)
	{
		if (interrupt.vector() == exception_vector::invalid_opcode)//用#UD代替int3  可能会和r3的中断冲突
		{
			if (ssdthook != nullptr && ssdthook->ssdtpoint.count(vp.context().rip_as_pointer))
			{
				vp.context().rip = (ULONG64)ssdthook->ssdtpoint[vp.context().rip_as_pointer];
				vp.suppress_rip_adjust();
				return;
			}
		}
	}

	base_type::handle_exception_or_nmi(vp);
}

auto vmexit_custom_handler::user_data(vcpu_t& vp) noexcept -> per_vcpu_data&
{
	return *reinterpret_cast<per_vcpu_data*>(vp.user_data());
}
