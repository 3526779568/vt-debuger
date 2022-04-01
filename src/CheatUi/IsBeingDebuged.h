#pragma once
#ifndef ISBEINGDEBUGED_H
#define ISBEINGDEBUGED_H
#include <Windows.h>
#include <cstdio>
#include "Scylla/NtApiShim.h"
#include "Scylla/OsInfo.h"
#include "Scylla/Peb.h"
#include "Scylla/Util.h"
#include "3rdparty/ntdll/ntdll.h"
#endif // !ISBEINGDEBUGED_H

BOOL CheckDebugALL();