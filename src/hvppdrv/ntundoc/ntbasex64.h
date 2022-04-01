#pragma once
#include "ntundoc/ntwin7x64.h"
#include "ntundoc/ntwin101703x64.h"
#include "ntundoc/ntwin101709x64.h"
#include "ntundoc/ntwin101803x64.h"
#include "ntundoc/ntwin101809x64.h"
#include "ntundoc/ntwin101903x64.h"
#include "ntundoc/ntwin101909x64.h"
#include <type_traits>

//namespace ntwinx64
//{
//  template<int build>
//  using EPROCESS = std::conditional<build == 15063, ntwin101703x64::EPROCESS,
//    std::conditional<build == 16299, ntwin101709x64::EPROCESS,
//    std::conditional<build == 17134, ntwin101803x64::EPROCESS,
//    std::conditional<build == 17763, ntwin101809x64::_EPROCESS,
//    std::conditional<build == 18363, ntwin101909x64::EPROCESS,
//    std::conditional<build == 18362, ntwin10_1903::EPROCESS,
//    std::conditional<build == 7601, ntwin7x64::EPROCESS, bool>
//    >
//    >
//    >
//    >
//    >
//  >;
//
//  template<int build>
//  using ETHREAD = std::conditional<build == 15063, ntwin101703x64::ETHREAD,
//    std::conditional<build == 16299, ntwin101709x64::ETHREAD,
//    std::conditional<build == 17134, ntwin101803x64::ETHREAD,
//    std::conditional<build == 17763, ntwin101809x64::_ETHREAD,
//    std::conditional<build == 18363, ntwin101909x64::ETHREAD,
//    std::conditional<build == 18362, ntwin10_1903::ETHREAD,
//    std::conditional<build == 7601, ntwin7x64::ETHREAD, bool>
//    >
//    >
//    >
//    >
//    >
//  >;
//}
