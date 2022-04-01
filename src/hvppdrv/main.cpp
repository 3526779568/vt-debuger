#include "Stowaways.h"
#include <globalobject.h>


#include <hvpp/hypervisor.h>

#include <hvpp/lib/driver.h>
#include <hvpp/lib/assert.h>
#include <hvpp/lib/log.h>
#include <hvpp/lib/mm.h>
#include <hvpp/lib/mp.h>

#include "vmexit_custom.h"
#include "device_custom.h"

#include <cinttypes>
#include "NoTraceBP.h"
#include <ddyutil.h>


using namespace ia32;
using namespace hvpp;

extern MemoryHide hide;
extern ddy::Util util;
DeviceOBJ *dev;
extern "C" PDRIVER_OBJECT GlobalDriverObject;
extern "C"  PUNICODE_STRING GlobalRegistryPath;
extern map<PEPROCESS, PVOID> CEDebugPort;

namespace driver
{
  //
  // Create combined handler from these VM-exit handlers.
  //
  using vmexit_handler_t = vmexit_compositor_handler<
    vmexit_stats_handler,
    vmexit_dbgbreak_handler,
    vmexit_custom_handler
    >;

  static_assert(std::is_base_of_v<vmexit_handler, vmexit_handler_t>);

  vmexit_handler_t* vmexit_handler_  = nullptr;
  device_custom*    device_          = nullptr;

  auto initialize() noexcept -> error_code_t
  {
    GlobalObjectInitialization();


    dev = new DeviceOBJ(GlobalDriverObject);
    //auto status = callback.RegistCallBackPre();

    //
    // Create device instance.
    //
    device_ = new device_custom();

    if (!device_)
    {
      destroy();
      return make_error_code_t(std::errc::not_enough_memory);
    }

    //
    // Initialize device instance.
    //
    if (auto err = device_->create())
    {
      destroy();
      return err;
    }

    //
    // Create VM-exit handler instance.
    //
    vmexit_handler_ = new vmexit_handler_t();

    if (!vmexit_handler_)
    {
      destroy();
      return make_error_code_t(std::errc::not_enough_memory);
    }

    //
    // Assign the vmexit_dbgbreak_handler instance to the device.
    //
    device_->handler(std::get<vmexit_dbgbreak_handler>(vmexit_handler_->handlers));

    //
    // Example: Enable tracing of I/O instructions.
    //
    //std::get<vmexit_stats_handler>(vmexit_handler_->handlers)
    //  .trace_bitmap().set(int(vmx::exit_reason::execute_io_instruction));
    


    //
    // Start the hypervisor.
    //
    if (auto err = hvpp::hypervisor::start(*vmexit_handler_))
    {
      destroy();
      return err;
    }

    //
    // Tell debugger we're started.
    //
   /* hvpp_info("Hypervisor started, current free memory: %" PRIu64 " MB",
               mm::hypervisor_allocator()->free_bytes() / 1024 / 1024);*/

    return {};
  }

  void destroy() noexcept
  {
    hide.~MemoryHide();
    GlobalObjectTermination();
    //
    // Stop the hypervisor.
    //
    hvpp::hypervisor::stop();

    //
    // Destroy VM-exit handler.
    //
    if (vmexit_handler_)
    {
      //
      // Print statistics into debugger.
      //
      std::get<vmexit_stats_handler>(vmexit_handler_->handlers).dump();

      delete vmexit_handler_;
    }

    //
    // Destroy device.
    //
    if (device_)
    {
      delete device_;
    }

    //hvpp_info("Hypervisor stopped");
  }
}
