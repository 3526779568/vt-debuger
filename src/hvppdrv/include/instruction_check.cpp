#include "instruction_check.h"
#include "intrin.h"

ddy::CheckInstruction::CheckInstruction()
{

}

ddy::CheckInstruction::~CheckInstruction()
{
}

bool ddy::CheckInstruction::CheckInvpcid()
{
	long info[4];
	__cpuidex((int*)info, 7, 0);
	if (_bittest(&info[1],10))
	{
		return true;
	}
	return false;
}
