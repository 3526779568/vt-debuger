#pragma once
#include <ntifs.h>
#include "HyperPlatform/util.h"
#ifndef PROCESSUTIL_H_
#define PROCESSUTIL_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va,Size) \
    ((BYTE_OFFSET (Va) + ((SIZE_T) (Size)) + (PAGE_SIZE - 1)) >> PAGE_SHIFT)

	_Use_decl_annotations_ HardwarePte* UtilAddressToPte(void* address);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif // !PROCESSUTIL_H_
