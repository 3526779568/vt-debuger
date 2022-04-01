.code

PreNtReadVirtualMemory proc
	db  100 dup(0cch)
PreNtReadVirtualMemory endp

PreNtWriteVirtualMemory proc
	db  100 dup(0cch)
PreNtWriteVirtualMemory endp

PreNtQueryInformationThread proc
	db  100 dup(0cch)
PreNtQueryInformationThread endp

PreNtGetContextThread proc
	db  100 dup(0cch)
PreNtGetContextThread endp

PreNtSetContextThread proc
	db  100 dup(0cch)
PreNtSetContextThread endp

PreNtSetInformationThread proc
	db 100 dup(0cch)
PreNtSetInformationThread endp

PreNtDebugActiveProcess proc
  db 100 dup(0cch)
PreNtDebugActiveProcess endp

PreNtQueryInformationProcess proc
  db 100 dup(0cch)
PreNtQueryInformationProcess endp

PreKiDispatchException proc
  db 100 dup(0cch)
PreKiDispatchException endp

PreDbgkForwardException proc
  db 100 dup(0cch)
PreDbgkForwardException endp

end
