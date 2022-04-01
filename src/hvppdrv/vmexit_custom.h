#pragma once
#include <hvpp/config.h>
#include <hvpp/vcpu.h>
#include <hvpp/vmexit.h>
#include <hvpp/vmexit/vmexit_stats.h>
#include <hvpp/vmexit/vmexit_dbgbreak.h>
#include <hvpp/vmexit/vmexit_passthrough.h>

using namespace ia32;
using namespace hvpp;

class vmexit_custom_handler
  : public vmexit_passthrough_handler
{
  public:
    using base_type = vmexit_passthrough_handler;

    auto setup(vcpu_t& vp) noexcept -> error_code_t override;
    void teardown(vcpu_t& vp) noexcept override;

    void handle_execute_cpuid(vcpu_t& vp) noexcept override;
    void handle_execute_vmcall(vcpu_t& vp) noexcept override;
    void handle_ept_violation(vcpu_t& vp) noexcept override;
    void handle_exception_or_nmi(vcpu_t& vp) noexcept override;
    void handle_monitor_trap_flag(vcpu_t& vp) noexcept override;
    void handle_mov_cr(vcpu_t& vp) noexcept override;
    void handle_mov_dr(vcpu_t& vp) noexcept override;
    void handle_gdtr_idtr_access(vcpu_t& vp) noexcept override;
    void handle_ldtr_tr_access(vcpu_t& vp) noexcept override;
    void handle_execute_invpcid(vcpu_t& vp) noexcept override;
    void handle_execute_rdtsc(vcpu_t& vp) noexcept override;
    void handle_execute_rdtscp(vcpu_t& vp) noexcept override;
    void handle_execute_wbinvd(vcpu_t& vp) noexcept override;
    void handle_execute_xsetbv(vcpu_t& vp) noexcept override;
    void handle_execute_rdmsr(vcpu_t& vp) noexcept override;
    void handle_execute_wrmsr(vcpu_t& vp) noexcept override;
    void handle_execute_io_instruction(vcpu_t& vp) noexcept override;
    void handle_execute_invd(vcpu_t& vp) noexcept override;
    void handle_execute_invlpg(vcpu_t& vp) noexcept override;

    //
    // VM-instructions.
    //
    void handle_execute_vmclear(vcpu_t& vp) noexcept override;
    void handle_execute_vmlaunch(vcpu_t& vp) noexcept override;
    void handle_execute_vmptrld(vcpu_t& vp) noexcept override;
    void handle_execute_vmptrst(vcpu_t& vp) noexcept override;
    void handle_execute_vmread(vcpu_t& vp) noexcept override;
    void handle_execute_vmresume(vcpu_t& vp) noexcept override;
    void handle_execute_vmwrite(vcpu_t& vp) noexcept override;
    void handle_execute_vmxoff(vcpu_t& vp) noexcept override;
    void handle_execute_vmxon(vcpu_t& vp) noexcept override;
    void handle_execute_invept(vcpu_t& vp) noexcept override;
    void handle_execute_invvpid(vcpu_t& vp) noexcept override;

  private:
    struct per_vcpu_data
    {
      ept_t ept;

      pa_t page_read;
      pa_t page_exec;
    };

    auto user_data(vcpu_t& vp) noexcept -> per_vcpu_data&;
};

void CreateDebugException(hvpp::vcpu_t& vp, const ia32::pa_t& guest_pa, ia32::va_t& guest_va, bool excute);
