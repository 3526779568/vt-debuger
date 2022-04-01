#include "ProcessUtil.h"
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

    static ULONG_PTR g_utilp_pxe_base = 0;
    static ULONG_PTR g_utilp_ppe_base = 0;
    static ULONG_PTR g_utilp_pde_base = 0;
    static ULONG_PTR g_utilp_pte_base = 0;

    static ULONG_PTR g_utilp_pxi_shift = 0;
    static ULONG_PTR g_utilp_ppi_shift = 0;
    static ULONG_PTR g_utilp_pdi_shift = 0;
    static ULONG_PTR g_utilp_pti_shift = 0;

    static ULONG_PTR g_utilp_pxi_mask = 0;
    static ULONG_PTR g_utilp_ppi_mask = 0;
    static ULONG_PTR g_utilp_pdi_mask = 0;
    static ULONG_PTR g_utilp_pti_mask = 0;
    /// Checks if a system is x64
/// @return true if a system is x64
    constexpr bool IsX64() {
#if defined(_AMD64_)
        return true;
#else
        return false;
#endif
    }

    // Checks whether the address is the canonical address
    _Use_decl_annotations_ static bool UtilpIsCanonicalFormAddress(void* address) {
        if constexpr (!IsX64()) {
            return true;
        }
        else {
            return !UtilIsInBounds(0x0000800000000000ull, 0xffff7fffffffffffull,
                reinterpret_cast<ULONG64>(address));
        }
    }

    // Return an address of PXE
    _Use_decl_annotations_ static HardwarePte* UtilpAddressToPxe(
        const void* address) {
        const auto addr = reinterpret_cast<ULONG_PTR>(address);
        const auto pxe_index = (addr >> g_utilp_pxi_shift)& g_utilp_pxi_mask;
        const auto offset = pxe_index * sizeof(HardwarePte);
        return reinterpret_cast<HardwarePte*>(g_utilp_pxe_base + offset);
    }

    // Return an address of PPE
    _Use_decl_annotations_ static HardwarePte* UtilpAddressToPpe(
        const void* address) {
        const auto addr = reinterpret_cast<ULONG_PTR>(address);
        const auto ppe_index = (addr >> g_utilp_ppi_shift)& g_utilp_ppi_mask;
        const auto offset = ppe_index * sizeof(HardwarePte);
        return reinterpret_cast<HardwarePte*>(g_utilp_ppe_base + offset);
    }

    // Return an address of PDE
    _Use_decl_annotations_ static HardwarePte* UtilpAddressToPde(
        const void* address) {
        const auto addr = reinterpret_cast<ULONG_PTR>(address);
        const auto pde_index = (addr >> g_utilp_pdi_shift)& g_utilp_pdi_mask;
        const auto offset = pde_index * sizeof(HardwarePte);
        return reinterpret_cast<HardwarePte*>(g_utilp_pde_base + offset);
    }

    // Return an address of PTE
    _Use_decl_annotations_ static HardwarePte* UtilpAddressToPte(
        const void* address) {
        const auto addr = reinterpret_cast<ULONG_PTR>(address);
        const auto pte_index = (addr >> g_utilp_pti_shift)& g_utilp_pti_mask;
        const auto offset = pte_index * sizeof(HardwarePte);
        return reinterpret_cast<HardwarePte*>(g_utilp_pte_base + offset);
    }

// NOTE This function is a recreation of UtilIsAccessibleAddress which returns
//  the hardware PTE.
    _Use_decl_annotations_ HardwarePte* UtilAddressToPte(void* address)
    {
        if (!UtilpIsCanonicalFormAddress(address)) {
            return NULL;
        }

        if constexpr (IsX64()) {
            const auto pxe = UtilpAddressToPxe(address);
            const auto ppe = UtilpAddressToPpe(address);
            if (!pxe||!ppe)
            {
                return NULL;
            }
            if (!pxe->valid || !ppe->valid) {
                return NULL;
            }
        }

        const auto pde = UtilpAddressToPde(address);
        const auto pte = UtilpAddressToPte(address);
        if (!pde)
        {
            return NULL;
        }
        if (!pde->valid) {
            return NULL;
        }
        if (pde->large_page) {
            return pte;  // A large page is always memory resident
        }
        if (!pte || !pte->valid) {
            return NULL;
        }
        return pte;
    }
#ifdef __cplusplus
}
#endif // __cplusplus