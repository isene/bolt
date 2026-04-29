; ============================================================================
; bolt — pure x86_64 NASM screen locker for the CHasm desktop suite.
;
; Connects to X11, creates a fullscreen override-redirect window covering
; root, grabs keyboard + pointer, and waits for the user to type their
; password. On Enter, pipes the typed bytes to a tiny suid C helper
; (bolt-auth) which calls crypt() against the shadow entry. Helper exit
; status decides whether we ungrab+exit (correct password) or shake the
; dot row red (wrong) and keep the lock up.
;
; No libc, no toolkits, just direct syscalls + the X11 wire protocol.
;
; Build: nasm -f elf64 bolt.asm -o bolt.o && ld bolt.o -o bolt
; ============================================================================

BITS 64
DEFAULT REL

; ---- Linux x86_64 syscalls --------------------------------------------------
%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_OPEN        2
%define SYS_CLOSE       3
%define SYS_FSTAT       5
%define SYS_POLL        7
%define SYS_MMAP        9
%define SYS_MUNMAP      11
%define SYS_PIPE        22
%define SYS_DUP2        33
%define SYS_NANOSLEEP   35
%define SYS_FORK        57
%define SYS_EXECVE      59
%define SYS_EXIT        60
%define SYS_WAIT4       61
%define SYS_KILL        62
%define SYS_FCNTL       72
%define F_SETFL         4
%define O_NONBLOCK      0x800
%define WNOHANG         1
%define SYS_SOCKET      41
%define SYS_CONNECT     42

%define O_RDONLY        0
%define O_WRONLY        1
%define O_CREAT         0x40
%define O_APPEND        0x400

%define AF_UNIX         1
%define SOCK_STREAM     1

%define PROT_READ       1
%define PROT_WRITE      2
%define MAP_PRIVATE     2
%define MAP_ANONYMOUS   0x20

; ---- X11 opcodes / event types ---------------------------------------------
%define X11_CREATE_WINDOW       1
%define X11_DESTROY_WINDOW      4
%define X11_MAP_WINDOW          8
%define X11_GET_GEOMETRY        14
%define X11_QUERY_TREE          15
%define X11_INTERN_ATOM         16
%define X11_CHANGE_PROPERTY     18
%define X11_GRAB_POINTER        26
%define X11_UNGRAB_POINTER      27
%define X11_GRAB_KEYBOARD       31
%define X11_UNGRAB_KEYBOARD     32
%define X11_OPEN_FONT           45
%define X11_QUERY_FONT          47
%define X11_QUERY_TEXT_EXTENTS  48
%define X11_CREATE_PIXMAP       53
%define X11_FREE_PIXMAP         54
%define X11_CREATE_GC           55
%define X11_CHANGE_GC           56
%define X11_FREE_GC             60
%define X11_COPY_AREA           62
%define X11_CLEAR_AREA          61
%define X11_POLY_FILL_RECT      70
%define X11_PUT_IMAGE           72
%define X11_POLY_TEXT_8         74
%define X11_GET_KEYBOARD_MAPPING 101

%define EV_KEY_PRESS            2
%define EV_EXPOSE               12
%define EV_MAP_NOTIFY           19
%define EV_CONFIGURE_NOTIFY     22

; CreateWindow value mask bits
%define CW_BACK_PIXEL           0x0002
%define CW_OVERRIDE_REDIRECT    0x0200
%define CW_EVENT_MASK           0x0800

; Event mask bits we want to receive
%define EVMASK_KEY_PRESS        0x0001
%define EVMASK_EXPOSURE         0x8000
%define EVMASK_STRUCTURE_NOTIFY 0x20000

; CreateGC value mask
%define GC_FOREGROUND           0x00000004
%define GC_BACKGROUND           0x00000008
%define GC_FONT                 0x00004000

; ---- Layout constants ------------------------------------------------------
%define MAX_PASSWORD_LEN        256
%define DOT_RADIUS              7
%define DOT_GAP                 18
%define DOT_Y_FROM_BOTTOM       60     ; centred — actually "centre y" param
%define LOGO_Y_FROM_TOP         100
%define TAGLINE_Y_FROM_LOGO     120

; ============================================================================
; BSS — all state is statically allocated.
; ============================================================================
SECTION .bss
align 8

; ---- X11 connection state --------------------------------------------------
x11_fd:                 resq 1
x11_seq:                resd 1
x11_rid_base:           resd 1
x11_rid_mask:           resd 1
x11_rid_next:           resd 1

root_window:            resd 1
root_visual:            resd 1
root_depth:             resb 1
                        resb 7              ; pad to 8
screen_w:               resw 1
screen_h:               resw 1
                        resd 1              ; pad

; Allocated XIDs
win_id:                 resd 1
gc_bg:                  resd 1              ; GC for bg fill
gc_fg:                  resd 1              ; GC for dots / logo / accent
gc_text:                resd 1              ; GC for tagline (with font)
font_id:                resd 1
bg_pixmap:              resd 1              ; server-side composed bg
gc_pix:                 resd 1              ; GC bound to bg_pixmap
composed_bg_ptr:        resq 1              ; mmap'd compose buffer (BGRX)

; Keyboard mapping: keysyms_per_keycode * (max_keycode-min_keycode+1) words.
; Standard X11: min_keycode = 8, max_keycode <= 255, kpkc = 4. Cap buf at
; 256 keycodes * 4 keysyms * 4 bytes = 4096 bytes.
min_keycode:            resd 1
max_keycode:            resd 1
keysyms_per_keycode:    resd 1
keymap_buf:             resd 8192           ; 32768 bytes — generous for any real keymap

; ---- Fingerprint verifier subprocess --------------------------------------
; Spawned once at lock start (fork → exec /usr/bin/fprintd-verify). The
; event loop poll()s its stdout pipe so a touch on the reader can unlock
; without the user typing a password. fp_pid==0 means no fingerprint
; child running (either disabled, or it already exited).
fp_pid:                 resd 1              ; child pid (0 = none)
fp_pipe_rd:             resd 1              ; pipe read end (we discard the bytes)
fp_active:              resb 1              ; 1 while the child is alive
                        resb 7              ; pad

; Logo blob mmap'd from img/logo.rgba (set up at install time).
logo_addr:              resq 1
logo_size:              resq 1
logo_w:                 resw 1
logo_h:                 resw 1

; Background image (optional, raw RGB matching screen geometry).
bg_addr:                resq 1
bg_size:                resq 1

; ---- Configuration (loaded from ~/.lockrc) ---------------------------------
cfg_bg_color:           resd 1              ; ARGB; default 0xff1a1b26
cfg_accent:             resd 1              ; default 0xff88c0d0
cfg_text_color:         resd 1              ; default 0xffd8dee9
cfg_tagline:            resb 128            ; NUL-terminated
cfg_bg_image:           resb 256            ; path; empty = no image
cfg_font_name:          resb 256            ; X11 core font, default is fixed

; ---- Input state -----------------------------------------------------------
password_buf:           resb MAX_PASSWORD_LEN
password_len:           resq 1

state_flag:             resb 1              ; 0=accepting, 1=checking, 2=fail-flash
                        resb 7              ; pad
fail_until_ms:          resq 1              ; fail flash expires at this monotonic ms

; ---- I/O scratch -----------------------------------------------------------
x11_write_buf:          resb 32768
x11_write_pos:          resq 1
x11_read_buf:           resb 32768
ev_buf:                 resb 32             ; one event at a time

tmp_buf:                resb 4096
config_buf:             resb 4096           ; raw .lockrc contents

; Scratch buffer for PutImage — must hold the whole image bytestream
; (header + pixel data) for one request. 96x96 logo = 36k; allow 256k
; so users can also use up-to-256x256 logo or similar.
put_image_buf:          resb 262144

; envp (saved at _start)
envp:                   resq 1
home_path:              resb 256

; logo + bg image paths
logo_path_buf:          resb 512

; Logo dim sidecar contents (ASCII).
logo_dim_buf:           resb 64

; ============================================================================
; .data — string literals
; ============================================================================
SECTION .data
align 8

x11_socket_prefix:      db "/tmp/.X11-unix/X", 0
x11_socket_prefix_len   equ $ - x11_socket_prefix - 1
default_lockrc_name:    db "/.lockrc", 0
logo_path_suffix:       db "/.cache/chasm-bolt/logo.rgba", 0
logo_path_install:      db "/usr/local/share/bolt/logo.rgba", 0
logo_path_dev:          db "/home/geir/Main/G/GIT-isene/bolt/img/logo.rgba", 0
logo_dim_path_dev:      db "/home/geir/Main/G/GIT-isene/bolt/img/logo.dim", 0

default_tagline:        db "Make it Simple", 0
default_tagline_len     equ $ - default_tagline - 1

default_font_name:      db "-*-fixed-bold-r-normal-*-20-*-*-*-*-*-*-*", 0
default_font_name_len   equ $ - default_font_name - 1

bolt_auth_path:         db "/usr/local/bin/bolt-auth", 0
bolt_auth_argv:         dq bolt_auth_path
                        dq 0

; Fingerprint verifier — fprintd-verify is a stock dbus client to fprintd.
; Exits 0 on a matching touch, non-zero on mismatch / kill / no enrolment.
fp_path:                db "/usr/bin/fprintd-verify", 0
fp_argv:                dq fp_path
                        dq 0
devnull_path:           db "/dev/null", 0

err_no_display:         db "bolt: cannot connect to X server", 10
err_no_display_len      equ $ - err_no_display

err_grab:               db "bolt: failed to grab keyboard/pointer (another locker?)", 10
err_grab_len            equ $ - err_grab

; ============================================================================
; .text
; ============================================================================
SECTION .text
global _start

; ----------------------------------------------------------------------------
; _start
; ----------------------------------------------------------------------------
_start:
    ; Stack at entry:  argc, argv[0..argc], NULL, env[0..], NULL
    mov rdi, [rsp]                  ; argc
    lea rsi, [rsp + 8]              ; argv
    lea rax, [rdi + 1]
    lea rcx, [rsi + rax*8]
    mov [envp], rcx

    ; Set defaults before reading config so missing keys keep working values.
    mov dword [cfg_bg_color], 0xff1a1b26
    mov dword [cfg_accent],   0xff88c0d0
    mov dword [cfg_text_color], 0xffd8dee9
    lea rdi, [cfg_tagline]
    lea rsi, [default_tagline]
    call str_copy
    lea rdi, [cfg_font_name]
    lea rsi, [default_font_name]
    call str_copy
    mov byte [cfg_bg_image], 0

    call resolve_home               ; fills home_path
    call load_config

    call x11_connect                ; → x11_fd, root_window, screen_w/h, etc
    test rax, rax
    jnz .die_no_display

    call load_keymap
    call create_lock_window
    call create_gcs
    call open_font
    call load_logo
    call load_bg_image

    ; DEBUG: dump key state to stderr.
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    lea rdi, [tmp_buf]
    mov dword [rdi], 'cfg='
    add rdi, 4
    lea rsi, [cfg_bg_image]
.dbg_cp:
    movzx eax, byte [rsi]
    test al, al
    jz .dbg_cp_done
    mov [rdi], al
    inc rsi
    inc rdi
    jmp .dbg_cp
.dbg_cp_done:
    mov dword [rdi], ' bg='
    add rdi, 4
    mov rax, [bg_addr]
    call write_hex_to_rdi
    mov dword [rdi], ' lg='
    add rdi, 4
    mov rax, [logo_addr]
    call write_hex_to_rdi
    mov dword [rdi], ' wh='
    add rdi, 4
    movzx eax, word [screen_w]
    call write_dec_to_rdi
    mov byte [rdi], 'x'
    inc rdi
    movzx eax, word [screen_h]
    call write_dec_to_rdi
    mov byte [rdi], 10
    inc rdi
    lea rsi, [tmp_buf]
    mov rdx, rdi
    sub rdx, rsi
    mov rax, SYS_WRITE
    mov rdi, 2
    syscall
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    call compose_and_upload_bg      ; build wallpaper+logo into bg_pixmap

    call grab_input                 ; retries; bails if can't grab in ~5s
    test rax, rax
    jnz .die_grab

    call render_screen
    ; Spawn fprintd-verify in the background so a fingerprint touch
    ; can unlock without typing. Falls through silently on systems
    ; without fprintd installed.
    call fp_start
    call event_loop

    ; event_loop returns on success.
    call fp_stop                          ; kill fingerprint child if still alive
    call ungrab_input
    mov rax, SYS_EXIT
    xor edi, edi
    syscall

.die_no_display:
    mov rax, SYS_WRITE
    mov rdi, 2
    lea rsi, [err_no_display]
    mov rdx, err_no_display_len
    syscall
    mov rax, SYS_EXIT
    mov edi, 1
    syscall

.die_grab:
    mov rax, SYS_WRITE
    mov rdi, 2
    lea rsi, [err_grab]
    mov rdx, err_grab_len
    syscall
    mov rax, SYS_EXIT
    mov edi, 2
    syscall

; ----------------------------------------------------------------------------
; resolve_home — finds HOME=... in envp, copies into home_path.
; If not found leaves home_path empty (bolt then uses $HOME-less paths).
; ----------------------------------------------------------------------------
resolve_home:
    mov byte [home_path], 0
    mov rcx, [envp]
.rh_loop:
    mov rdi, [rcx]
    test rdi, rdi
    jz .rh_done
    cmp dword [rdi], 'HOME'
    jne .rh_next
    cmp byte [rdi+4], '='
    jne .rh_next
    add rdi, 5
    lea rsi, [home_path]
    mov edx, 255
.rh_cp:
    test edx, edx
    jz .rh_done
    mov al, [rdi]
    test al, al
    jz .rh_term
    mov [rsi], al
    inc rdi
    inc rsi
    dec edx
    jmp .rh_cp
.rh_term:
    mov byte [rsi], 0
    ret
.rh_next:
    add rcx, 8
    jmp .rh_loop
.rh_done:
    ret

; ----------------------------------------------------------------------------
; load_config — read $HOME/.lockrc (best effort) and parse "key = value".
; Recognised keys: bg_color, accent, text_color, tagline, bg_image, font.
; Colour values are 0xRRGGBB hex (ARGB high byte forced to 0xff).
; Anything unrecognised is silently ignored — config files are forward-
; compatible with future bolt versions.
; ----------------------------------------------------------------------------
load_config:
    push rbx
    push r12
    push r13
    push r14
    ; Build path = home_path + "/.lockrc"
    lea rdi, [tmp_buf]
    lea rsi, [home_path]
    call str_copy_ptr               ; rdi advanced past NUL? returns rdi=end
    mov rdi, rax
    lea rsi, [default_lockrc_name]
    call str_copy

    mov rax, SYS_OPEN
    lea rdi, [tmp_buf]
    xor esi, esi                    ; O_RDONLY
    syscall
    test rax, rax
    js .lc_done
    mov r12, rax                    ; fd
    ; Read up to 4096 bytes
    mov rax, SYS_READ
    mov rdi, r12
    lea rsi, [config_buf]
    mov rdx, 4095
    syscall
    test rax, rax
    js .lc_close
    mov r13, rax
    mov byte [config_buf + r13], 0  ; NUL-terminate

    ; Parse lines.
    lea rbx, [config_buf]
    lea r14, [config_buf + r13]     ; end ptr
.lc_lineloop:
    cmp rbx, r14
    jge .lc_close
    ; Skip leading whitespace
.lc_skipws:
    cmp byte [rbx], ' '
    je .lc_advws
    cmp byte [rbx], 9
    jne .lc_check_comment
.lc_advws:
    inc rbx
    cmp rbx, r14
    jl .lc_skipws
    jmp .lc_close
.lc_check_comment:
    cmp byte [rbx], '#'
    je .lc_skip_line
    cmp byte [rbx], 10
    je .lc_eol
    cmp byte [rbx], 0
    je .lc_close
    ; rbx now at start of "key = value". lc_parse_kv returns the next
    ; iterator position in rax (one past the line's '\n' or at NUL).
    mov rdi, rbx
    call lc_parse_kv
    test rax, rax
    jz .lc_close                    ; defensive — shouldn't happen
    mov rbx, rax
    jmp .lc_lineloop
.lc_skip_line:
    cmp rbx, r14
    jge .lc_close
    cmp byte [rbx], 10
    je .lc_eol
    inc rbx
    jmp .lc_skip_line
.lc_eol:
    inc rbx
    jmp .lc_lineloop

.lc_close:
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall
.lc_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; lc_parse_kv — rdi at start of "<key> = <value>\n". Updates [rbx] (the
; load_config iterator) past the line. Recognises five keys.
; ----------------------------------------------------------------------------
lc_parse_kv:
    push rbx
    push r12
    push r13
    mov r12, rdi                    ; start of key
    ; Find '=' on this line.
    mov rax, rdi
.kv_findeq:
    movzx ecx, byte [rax]
    test cl, cl
    jz .kv_done
    cmp cl, 10
    je .kv_done
    cmp cl, '='
    je .kv_have_eq
    inc rax
    jmp .kv_findeq
.kv_have_eq:
    mov r13, rax                    ; '=' position
    ; Trim trailing whitespace before '=' to find key end.
    mov rcx, r13
    dec rcx
.kv_trim_key:
    cmp rcx, r12
    jl .kv_done
    movzx eax, byte [rcx]
    cmp al, ' '
    je .kv_trim_more
    cmp al, 9
    je .kv_trim_more
    jmp .kv_key_end
.kv_trim_more:
    dec rcx
    jmp .kv_trim_key
.kv_key_end:
    inc rcx                          ; rcx = one past last key char
    ; key is [r12 .. rcx)
    ; value: skip past '=' and leading ws
    lea rdi, [r13 + 1]
.kv_vskip:
    movzx eax, byte [rdi]
    cmp al, ' '
    je .kv_vsadv
    cmp al, 9
    jne .kv_vstart
.kv_vsadv:
    inc rdi
    jmp .kv_vskip
.kv_vstart:
    ; rdi = value start, find end-of-line.
    mov rsi, rdi
.kv_veol:
    movzx eax, byte [rsi]
    test al, al
    jz .kv_vend
    cmp al, 10
    je .kv_vend
    inc rsi
    jmp .kv_veol
.kv_vend:
    ; Trim trailing whitespace from value.
    mov rdx, rsi
.kv_vtrim:
    cmp rdx, rdi
    jle .kv_dispatch
    movzx eax, byte [rdx - 1]
    cmp al, ' '
    je .kv_vtrim_back
    cmp al, 9
    je .kv_vtrim_back
    cmp al, 13
    je .kv_vtrim_back
    jmp .kv_dispatch
.kv_vtrim_back:
    dec rdx
    jmp .kv_vtrim
.kv_dispatch:
    ; r12 = key start, rcx = key end (exclusive)
    ; rdi = value start, rdx = value end (exclusive)
    ; Identify key and stash value.
    mov rax, rcx
    sub rax, r12                    ; key length
    cmp rax, 8
    jne .kv_try_accent
    cmp dword [r12],     'bg_c'
    jne .kv_try_accent
    cmp dword [r12 + 4], 'olor'
    jne .kv_try_accent
    call kv_parse_color
    test rax, rax
    js .kv_skip
    or eax, 0xff000000
    mov [cfg_bg_color], eax
    jmp .kv_skip
.kv_try_accent:
    cmp rax, 6
    jne .kv_try_text_color
    cmp dword [r12],     'acce'
    jne .kv_try_text_color
    cmp word  [r12 + 4], 'nt'
    jne .kv_try_text_color
    call kv_parse_color
    test rax, rax
    js .kv_skip
    or eax, 0xff000000
    mov [cfg_accent], eax
    jmp .kv_skip
.kv_try_text_color:
    cmp rax, 10
    jne .kv_try_tagline
    cmp dword [r12],      'text'
    jne .kv_try_tagline
    cmp dword [r12 + 4],  '_col'
    jne .kv_try_tagline
    cmp word  [r12 + 8],  'or'
    jne .kv_try_tagline
    call kv_parse_color
    test rax, rax
    js .kv_skip
    or eax, 0xff000000
    mov [cfg_text_color], eax
    jmp .kv_skip
.kv_try_tagline:
    cmp rax, 7
    jne .kv_try_bg_image
    cmp dword [r12],      'tagl'
    jne .kv_try_bg_image
    cmp word  [r12 + 4],  'in'
    jne .kv_try_bg_image
    cmp byte  [r12 + 6],  'e'
    jne .kv_try_bg_image
    push rdi                        ; copy [rdi..rdx) into cfg_tagline
    push rdx
    lea r10, [cfg_tagline]
    mov r11d, 127
.kv_tcp:
    cmp rdi, rdx
    jge .kv_tend
    test r11d, r11d
    jz .kv_tend
    movzx eax, byte [rdi]
    mov [r10], al
    inc rdi
    inc r10
    dec r11d
    jmp .kv_tcp
.kv_tend:
    mov byte [r10], 0
    pop rdx
    pop rdi
    jmp .kv_skip
.kv_try_bg_image:
    cmp rax, 8
    jne .kv_try_font
    cmp dword [r12],     'bg_i'
    jne .kv_try_font
    cmp dword [r12 + 4], 'mage'
    jne .kv_try_font
    push rdi
    push rdx
    lea r10, [cfg_bg_image]
    mov r11d, 255
.kv_bcp:
    cmp rdi, rdx
    jge .kv_bend
    test r11d, r11d
    jz .kv_bend
    movzx eax, byte [rdi]
    mov [r10], al
    inc rdi
    inc r10
    dec r11d
    jmp .kv_bcp
.kv_bend:
    mov byte [r10], 0
    pop rdx
    pop rdi
    jmp .kv_skip
.kv_try_font:
    cmp rax, 4
    jne .kv_skip
    cmp dword [r12], 'font'
    jne .kv_skip
    push rdi
    push rdx
    lea r10, [cfg_font_name]
    mov r11d, 255
.kv_fcp:
    cmp rdi, rdx
    jge .kv_fend
    test r11d, r11d
    jz .kv_fend
    movzx eax, byte [rdi]
    mov [r10], al
    inc rdi
    inc r10
    dec r11d
    jmp .kv_fcp
.kv_fend:
    mov byte [r10], 0
    pop rdx
    pop rdi
.kv_skip:
    mov rax, rsi                    ; one-past-EOL of the value
.kv_done:
    ; Normalize: if rax sits on '\n', step past it. Caller spins on rbx
    ; until it hits NUL, so we must hand it a position strictly past the
    ; line we just consumed, not on the line's terminator.
    cmp byte [rax], 0
    je .kv_ret
    cmp byte [rax], 10
    jne .kv_ret
    inc rax
.kv_ret:
    pop r13
    pop r12
    pop rbx                         ; restore CALLER's rbx
    ret

; Static sneak buffer used by lc_parse_kv to communicate the next-line
; offset back. load_config doesn't currently consult it; we'll wire that
; up if needed in a refactor.
SECTION .bss
rbx_p_save:             resq 1
SECTION .text

; ----------------------------------------------------------------------------
; kv_parse_color — rdi..rdx is "0xRRGGBB" (or "RRGGBB"). Returns rax = u32
; or -1 on parse failure.
; ----------------------------------------------------------------------------
kv_parse_color:
    push rbx
    mov rbx, rdi
    cmp rbx, rdx
    jge .pc_fail
    ; Skip leading "0x" if present.
    cmp byte [rbx], '0'
    jne .pc_loop
    lea rax, [rbx + 1]
    cmp rax, rdx
    jge .pc_loop
    cmp byte [rbx + 1], 'x'
    je .pc_skip0x
    cmp byte [rbx + 1], 'X'
    jne .pc_loop
.pc_skip0x:
    add rbx, 2
.pc_loop:
    xor eax, eax
.pc_digit:
    cmp rbx, rdx
    jge .pc_done
    movzx ecx, byte [rbx]
    cmp cl, '0'
    jl .pc_fail
    cmp cl, '9'
    jle .pc_dec
    or cl, 0x20                     ; lowercase
    cmp cl, 'a'
    jl .pc_fail
    cmp cl, 'f'
    jg .pc_fail
    sub cl, 'a' - 10
    jmp .pc_acc
.pc_dec:
    sub cl, '0'
.pc_acc:
    shl eax, 4
    or eax, ecx
    inc rbx
    jmp .pc_digit
.pc_done:
    pop rbx
    ret
.pc_fail:
    mov rax, -1
    pop rbx
    ret

; ----------------------------------------------------------------------------
; str_copy — rdi=dst, rsi=src (NUL-terminated). Copies including NUL.
; ----------------------------------------------------------------------------
str_copy:
.sc_loop:
    movzx eax, byte [rsi]
    mov [rdi], al
    test al, al
    jz .sc_done
    inc rsi
    inc rdi
    jmp .sc_loop
.sc_done:
    ret

; Variant returning rax = position of the written NUL (so callers can chain).
str_copy_ptr:
.scp_loop:
    movzx eax, byte [rsi]
    mov [rdi], al
    test al, al
    jz .scp_done
    inc rsi
    inc rdi
    jmp .scp_loop
.scp_done:
    mov rax, rdi
    ret

str_len:
    push rdi
    xor eax, eax
.sl_loop:
    cmp byte [rdi], 0
    je .sl_done
    inc rdi
    inc eax
    jmp .sl_loop
.sl_done:
    pop rdi
    ret

; ----------------------------------------------------------------------------
; x11_connect — open the X server unix socket, send the connection-setup
; request with no auth, parse the accepted reply, populate connection
; state. Returns rax = 0 on success, non-zero on failure.
; ----------------------------------------------------------------------------
x11_connect:
    push rbx
    push r12
    ; socket(AF_UNIX, SOCK_STREAM, 0)
    mov rax, SYS_SOCKET
    mov rdi, AF_UNIX
    mov rsi, SOCK_STREAM
    xor edx, edx
    syscall
    test rax, rax
    js .xc_fail
    mov [x11_fd], rax

    ; sockaddr_un on stack: family(2) + path(108)
    sub rsp, 112
    ; zero the buffer so we don't leak stack bytes through the kernel
    xor eax, eax
    mov rdi, rsp
    mov ecx, 14
    rep stosq
    mov word [rsp], AF_UNIX
    lea rdi, [rsp + 2]
    lea rsi, [x11_socket_prefix]
    call str_copy_ptr               ; rax = end ptr (at the trailing NUL)
    mov rdi, rax                    ; append display number from $DISPLAY
    call append_display_number      ; writes ASCII digits + NUL
    ; Compute exact addrlen = offsetof(sun_path) + strlen(path) + 1.
    lea rdi, [rsp + 2]
    call str_len                    ; eax = strlen
    lea edx, [eax + 3]              ; +2 family +1 NUL
    mov rax, SYS_CONNECT
    mov rdi, [x11_fd]
    mov rsi, rsp
    syscall
    add rsp, 112
    test rax, rax
    js .xc_fail

    ; Send 12-byte connection request: byte-order='l', major=11, minor=0.
    sub rsp, 16
    mov byte  [rsp], 'l'
    mov byte  [rsp + 1], 0
    mov word  [rsp + 2], 11
    mov word  [rsp + 4], 0
    mov word  [rsp + 6], 0          ; auth proto name length = 0
    mov word  [rsp + 8], 0          ; auth data length = 0
    mov word  [rsp + 10], 0         ; pad
    mov rax, SYS_WRITE
    mov rdi, [x11_fd]
    mov rsi, rsp
    mov rdx, 12
    syscall
    add rsp, 16

    ; Read 8-byte reply header.
    mov rax, SYS_READ
    mov rdi, [x11_fd]
    lea rsi, [x11_read_buf]
    mov rdx, 8
    syscall
    cmp rax, 8
    jl .xc_fail
    cmp byte [x11_read_buf], 1      ; 1 = success
    jne .xc_fail
    movzx eax, word [x11_read_buf + 6]   ; additional data length in 4-byte units
    shl eax, 2                            ; bytes
    cmp eax, 32760
    ja .xc_fail
    mov r12, rax                          ; total additional bytes
    mov rdi, r12
    lea rsi, [x11_read_buf + 8]
    ; Read it in a loop.
.xc_drain:
    test rdi, rdi
    jz .xc_drained
    mov rax, SYS_READ
    push rdi
    push rsi
    mov rdx, rdi
    mov rdi, [x11_fd]
    syscall
    pop rsi
    pop rdi
    test rax, rax
    jle .xc_fail
    sub rdi, rax
    add rsi, rax
    jmp .xc_drain
.xc_drained:

    ; The setup info layout (after our 8-byte prefix):
    ;   +0  release-number (4)
    ;   +4  resource-id-base (4)
    ;   +8  resource-id-mask (4)
    ;   +12 motion-buffer-size (4)
    ;   +16 vendor-length (2)
    ;   +18 max-request-length (2)
    ;   +20 number-of-screens (1)
    ;   +21 number-of-formats (1)
    ;   +22 image-byte-order (1)
    ;   +23 bitmap-bit-order (1)
    ;   +24 bitmap-scanline-unit (1)
    ;   +25 bitmap-scanline-pad (1)
    ;   +26 min-keycode (1)
    ;   +27 max-keycode (1)
    ;   +28 pad (4)
    ;   +32 vendor (string, padded to 4)
    ;   then: pixmap-formats (8 bytes each * number-of-formats)
    ;   then: SCREEN0 (40 bytes + DEPTHs + ...)
    mov eax, [x11_read_buf + 8 + 4]
    mov [x11_rid_base], eax
    mov eax, [x11_read_buf + 8 + 8]
    mov [x11_rid_mask], eax
    mov [x11_rid_next], eax         ; next allocated id starts at base
    mov eax, [x11_rid_base]
    mov [x11_rid_next], eax
    movzx eax, byte [x11_read_buf + 8 + 26]
    mov [min_keycode], eax
    movzx eax, byte [x11_read_buf + 8 + 27]
    mov [max_keycode], eax

    ; Compute SCREEN0 offset = 8 + 32 + ((vendor-length + 3) & ~3) + formats * 8.
    movzx eax, word [x11_read_buf + 8 + 16]      ; vendor-length
    add eax, 3
    and eax, ~3
    add eax, 32
    movzx ecx, byte [x11_read_buf + 8 + 21]      ; formats
    imul ecx, 8
    add eax, ecx
    add eax, 8                                    ; account for our 8-byte header
    ; rax now = offset of SCREEN0 inside x11_read_buf.

    ; SCREEN0 layout:
    ;   +0  root (4)
    ;   +4  default-colormap (4)
    ;   +8  white-pixel (4)
    ;   +12 black-pixel (4)
    ;   +16 current-input-masks (4)
    ;   +20 width-in-pixels (2)
    ;   +22 height-in-pixels (2)
    ;   +24 width-in-mm (2)
    ;   +26 height-in-mm (2)
    ;   +28 min-installed-maps (2)
    ;   +30 max-installed-maps (2)
    ;   +32 root-visual (4)
    ;   +36 backing-stores (1)
    ;   +37 save-unders (1)
    ;   +38 root-depth (1)
    ;   +39 number-of-allowed-depths (1)
    lea r12, [x11_read_buf + rax]
    mov edx, [r12]
    mov [root_window], edx
    mov ecx, [r12 + 32]
    mov [root_visual], ecx
    movzx ecx, byte [r12 + 38]
    mov [root_depth], cl
    mov ax, [r12 + 20]
    mov [screen_w], ax
    mov ax, [r12 + 22]
    mov [screen_h], ax

    xor eax, eax
    pop r12
    pop rbx
    ret
.xc_fail:
    mov rax, 1
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; append_display_number — rdi points just past "/tmp/.X11-unix/X" in the
; sockaddr buffer. Reads $DISPLAY from envp (form ":<n>" or
; "host:<n>.<screen>"), writes <n> as ASCII digits + NUL, falls back to
; "0" if $DISPLAY is missing or unparseable.
; ----------------------------------------------------------------------------
append_display_number:
    push rbx
    mov rbx, rdi                    ; dst
    mov rcx, [envp]
.adn_loop:
    mov rdi, [rcx]
    test rdi, rdi
    jz .adn_default
    cmp dword [rdi], 'DISP'
    jne .adn_next
    cmp dword [rdi + 4], 'LAY='
    jne .adn_next
    add rdi, 8                      ; past "DISPLAY="
    ; Find ':' in the value.
.adn_findcolon:
    movzx eax, byte [rdi]
    test al, al
    jz .adn_default
    cmp al, ':'
    je .adn_have_colon
    inc rdi
    jmp .adn_findcolon
.adn_have_colon:
    inc rdi                         ; past ':'
    ; Read decimal digits.
    movzx eax, byte [rdi]
    sub al, '0'
    cmp al, 9
    ja .adn_default                 ; no digits → fallback
    ; Copy digit run.
.adn_cpy:
    movzx eax, byte [rdi]
    sub al, '0'
    cmp al, 9
    ja .adn_term
    add al, '0'
    mov [rbx], al
    inc rbx
    inc rdi
    jmp .adn_cpy
.adn_term:
    mov byte [rbx], 0
    pop rbx
    ret
.adn_next:
    add rcx, 8
    jmp .adn_loop
.adn_default:
    mov byte [rbx], '0'
    mov byte [rbx + 1], 0
    pop rbx
    ret

; ----------------------------------------------------------------------------
; alloc_xid — reserve a new resource ID. Returns rax = XID.
; ----------------------------------------------------------------------------
alloc_xid:
    mov eax, [x11_rid_next]
    inc dword [x11_rid_next]
    and eax, [x11_rid_mask]
    or  eax, [x11_rid_base]
    ret

; ----------------------------------------------------------------------------
; x11_buffer — append rdx bytes from rsi to write buffer. Auto-flushes
; when the buffer crosses the 28K mark so we never overflow.
; ----------------------------------------------------------------------------
x11_buffer:
    push rbx
    mov rbx, [x11_write_pos]
    lea rdi, [x11_write_buf + rbx]
    xor ecx, ecx
.xb_cp:
    cmp rcx, rdx
    jge .xb_done
    movzx eax, byte [rsi + rcx]
    mov [rdi + rcx], al
    inc rcx
    jmp .xb_cp
.xb_done:
    add rbx, rdx
    mov [x11_write_pos], rbx
    cmp rbx, 28000
    jl .xb_no_flush
    call x11_flush
.xb_no_flush:
    pop rbx
    ret

x11_flush:
    mov rdx, [x11_write_pos]
    test rdx, rdx
    jz .xf_done
    mov rax, SYS_WRITE
    mov rdi, [x11_fd]
    lea rsi, [x11_write_buf]
    syscall
    mov qword [x11_write_pos], 0
.xf_done:
    ret

; ----------------------------------------------------------------------------
; create_lock_window — fullscreen override-redirect window covering root.
; ----------------------------------------------------------------------------
create_lock_window:
    push rbx
    push r12
    call alloc_xid
    mov [win_id], eax
    mov r12d, eax

    lea rdi, [tmp_buf]
    mov byte [rdi], X11_CREATE_WINDOW
    mov byte [rdi + 1], 0           ; depth = CopyFromParent
    mov word [rdi + 2], 11          ; request length: 8 fixed + 3 values
    mov [rdi + 4], r12d             ; wid
    mov eax, [root_window]
    mov [rdi + 8], eax              ; parent
    mov word [rdi + 12], 0          ; x
    mov word [rdi + 14], 0          ; y
    mov ax, [screen_w]
    mov [rdi + 16], ax
    mov ax, [screen_h]
    mov [rdi + 18], ax
    mov word [rdi + 20], 0          ; border width
    mov word [rdi + 22], 1          ; class = InputOutput
    mov dword [rdi + 24], 0         ; visual = CopyFromParent
    mov dword [rdi + 28], CW_BACK_PIXEL | CW_OVERRIDE_REDIRECT | CW_EVENT_MASK
    mov eax, [cfg_bg_color]
    mov [rdi + 32], eax             ; back-pixel
    mov dword [rdi + 36], 1         ; override-redirect = TRUE
    mov dword [rdi + 40], EVMASK_KEY_PRESS | EVMASK_EXPOSURE | EVMASK_STRUCTURE_NOTIFY
    lea rsi, [tmp_buf]
    mov rdx, 44
    call x11_buffer
    inc dword [x11_seq]

    ; MapWindow
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_MAP_WINDOW
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 2
    mov [rdi + 4], r12d
    lea rsi, [tmp_buf]
    mov rdx, 8
    call x11_buffer
    inc dword [x11_seq]
    call x11_flush

    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; create_gcs — three GCs: bg fill, fg/dot/logo, text (with font).
; create_gcs has to come before open_font so gc_text exists; we then
; ChangeGC after the font opens.
; ----------------------------------------------------------------------------
create_gcs:
    ; gc_bg
    call alloc_xid
    mov [gc_bg], eax
    mov ebx, eax
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_CREATE_GC
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 5           ; 4 fixed + 1 value
    mov [rdi + 4], ebx
    mov eax, [win_id]
    mov [rdi + 8], eax
    mov dword [rdi + 12], GC_FOREGROUND
    mov eax, [cfg_bg_color]
    mov [rdi + 16], eax
    lea rsi, [tmp_buf]
    mov rdx, 20
    call x11_buffer
    inc dword [x11_seq]

    ; gc_fg
    call alloc_xid
    mov [gc_fg], eax
    mov ebx, eax
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_CREATE_GC
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 5
    mov [rdi + 4], ebx
    mov eax, [win_id]
    mov [rdi + 8], eax
    mov dword [rdi + 12], GC_FOREGROUND
    mov eax, [cfg_accent]
    mov [rdi + 16], eax
    lea rsi, [tmp_buf]
    mov rdx, 20
    call x11_buffer
    inc dword [x11_seq]

    ; gc_text — placeholder fg; font set in open_font.
    call alloc_xid
    mov [gc_text], eax
    mov ebx, eax
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_CREATE_GC
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 5
    mov [rdi + 4], ebx
    mov eax, [win_id]
    mov [rdi + 8], eax
    mov dword [rdi + 12], GC_FOREGROUND
    mov eax, [cfg_text_color]
    mov [rdi + 16], eax
    lea rsi, [tmp_buf]
    mov rdx, 20
    call x11_buffer
    inc dword [x11_seq]
    ret

; ----------------------------------------------------------------------------
; open_font — OpenFont with cfg_font_name, then ChangeGC on gc_text to
; install the font. Failure = silent fallthrough; tagline just won't
; render (no font set in the GC means the server uses the default).
; ----------------------------------------------------------------------------
open_font:
    push rbx
    push r12
    call alloc_xid
    mov [font_id], eax
    mov ebx, eax
    lea rdi, [cfg_font_name]
    call str_len                    ; eax = name length
    mov r12d, eax
    ; OpenFont request: opcode=45, pad, length=3+(name_len+3)/4, fid, name_len, pad, name…
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_OPEN_FONT
    mov byte [rdi + 1], 0
    mov eax, r12d
    add eax, 3
    shr eax, 2
    add eax, 3                      ; 3 fixed words (12 bytes)
    mov [rdi + 2], ax
    mov [rdi + 4], ebx              ; fid
    mov [rdi + 8], r12w             ; name length
    mov word [rdi + 10], 0          ; pad
    ; copy name
    lea rsi, [cfg_font_name]
    lea r10, [rdi + 12]
    xor ecx, ecx
.of_cp:
    cmp ecx, r12d
    jge .of_padded
    movzx eax, byte [rsi + rcx]
    mov [r10 + rcx], al
    inc ecx
    jmp .of_cp
.of_padded:
    mov eax, r12d
    add eax, 12
    add eax, 3
    and eax, ~3
    mov rdx, rax
    lea rsi, [tmp_buf]
    call x11_buffer
    inc dword [x11_seq]

    ; ChangeGC gc_text with font.
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_CHANGE_GC
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 4
    mov eax, [gc_text]
    mov [rdi + 4], eax
    mov dword [rdi + 8], GC_FONT
    mov [rdi + 12], ebx
    lea rsi, [tmp_buf]
    mov rdx, 16
    call x11_buffer
    inc dword [x11_seq]
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; load_logo — mmap img/logo.rgba (read-only) so render can blit it.
; Tries the dev path first, then the install path. Sets logo_addr=0 and
; logo_w=logo_h=0 on failure (render falls back gracefully).
; ----------------------------------------------------------------------------
load_logo:
    push rbx
    push r12
    push r13
    ; First try the dev path.
    mov rax, SYS_OPEN
    lea rdi, [logo_path_dev]
    xor esi, esi
    syscall
    test rax, rax
    jns .ll_have_fd
    mov rax, SYS_OPEN
    lea rdi, [logo_path_install]
    xor esi, esi
    syscall
    test rax, rax
    js .ll_fail
.ll_have_fd:
    mov rbx, rax                    ; fd
    sub rsp, 144                    ; struct stat
    mov rax, SYS_FSTAT
    mov rdi, rbx
    mov rsi, rsp
    syscall
    test rax, rax
    js .ll_fail_close_sp
    mov r12, [rsp + 48]             ; st_size
    add rsp, 144
    mov [logo_size], r12
    mov rax, SYS_MMAP
    xor edi, edi
    mov rsi, r12
    mov rdx, PROT_READ
    mov r10d, MAP_PRIVATE
    mov r8, rbx                     ; fd
    xor r9d, r9d
    syscall
    test rax, rax
    js .ll_fail_close
    mov [logo_addr], rax
    ; Read the .dim sidecar to get width / height.
    mov rax, SYS_OPEN
    lea rdi, [logo_dim_path_dev]
    xor esi, esi
    syscall
    test rax, rax
    js .ll_def_dim
    mov r13, rax
    mov rax, SYS_READ
    mov rdi, r13
    lea rsi, [logo_dim_buf]
    mov rdx, 63
    syscall
    push rax
    mov rax, SYS_CLOSE
    mov rdi, r13
    syscall
    pop rax
    test rax, rax
    js .ll_def_dim
    mov byte [logo_dim_buf + rax], 0
    ; Parse "WIDTH HEIGHT".
    lea rdi, [logo_dim_buf]
    call parse_decimal              ; rax=value, rdi advanced past digits
    mov [logo_w], ax
    ; Skip whitespace.
.ll_skipw:
    movzx ecx, byte [rdi]
    cmp cl, ' '
    je .ll_skipw_adv
    cmp cl, 9
    jne .ll_h_parse
.ll_skipw_adv:
    inc rdi
    jmp .ll_skipw
.ll_h_parse:
    call parse_decimal
    mov [logo_h], ax
    jmp .ll_close_dim
.ll_def_dim:
    mov word [logo_w], 96
    mov word [logo_h], 96
.ll_close_dim:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    pop r13
    pop r12
    pop rbx
    ret

.ll_fail_close_sp:
    add rsp, 144
.ll_fail_close:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.ll_fail:
    mov qword [logo_addr], 0
    mov word  [logo_w], 0
    mov word  [logo_h], 0
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; load_bg_image — mmap the path in cfg_bg_image (raw RGB matching screen
; geometry). Empty config leaves bg_addr=0; render falls back to bg_color.
; ----------------------------------------------------------------------------
load_bg_image:
    cmp byte [cfg_bg_image], 0
    je .lbi_skip
    push rbx
    mov rax, SYS_OPEN
    lea rdi, [cfg_bg_image]
    xor esi, esi
    syscall
    test rax, rax
    js .lbi_fail
    mov rbx, rax
    sub rsp, 144
    mov rax, SYS_FSTAT
    mov rdi, rbx
    mov rsi, rsp
    syscall
    test rax, rax
    js .lbi_fail_close_sp
    mov rcx, [rsp + 48]
    add rsp, 144
    mov [bg_size], rcx
    mov rax, SYS_MMAP
    xor edi, edi
    mov rsi, rcx
    mov rdx, PROT_READ
    mov r10d, MAP_PRIVATE
    mov r8, rbx
    xor r9d, r9d
    syscall
    test rax, rax
    js .lbi_fail_close
    mov [bg_addr], rax
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    pop rbx
    ret
.lbi_fail_close_sp:
    add rsp, 144
.lbi_fail_close:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.lbi_fail:
    mov qword [bg_addr], 0
    pop rbx
.lbi_skip:
    ret

; ----------------------------------------------------------------------------
; write_dec_to_rdi — eax=value, rdi=dst. Writes ASCII decimal, advances rdi.
; ----------------------------------------------------------------------------
write_dec_to_rdi:
    push rbx
    push rcx
    test eax, eax
    jnz .wd_nz
    mov byte [rdi], '0'
    inc rdi
    pop rcx
    pop rbx
    ret
.wd_nz:
    xor ecx, ecx
    mov ebx, 10
.wd_div:
    test eax, eax
    jz .wd_emit
    xor edx, edx
    div ebx
    add dl, '0'
    push rdx
    inc ecx
    jmp .wd_div
.wd_emit:
    test ecx, ecx
    jz .wd_done
    pop rdx
    mov [rdi], dl
    inc rdi
    dec ecx
    jmp .wd_emit
.wd_done:
    pop rcx
    pop rbx
    ret

write_hex_to_rdi:
    push rbx
    push rcx
    mov ebx, eax            ; preserve value
    mov ecx, 28
.wh_loop:
    mov eax, ebx
    shr eax, cl
    and eax, 0xF
    cmp al, 10
    jl .wh_dig
    add al, 'a' - 10 - '0'
.wh_dig:
    add al, '0'
    mov [rdi], al
    inc rdi
    sub ecx, 4
    jns .wh_loop
    pop rcx
    pop rbx
    ret

; ----------------------------------------------------------------------------
; parse_decimal — rdi at start of digits; returns rax = value, rdi past
; last digit. No sign / overflow handling — small integers only.
; ----------------------------------------------------------------------------
parse_decimal:
    xor eax, eax
.pd_loop:
    movzx ecx, byte [rdi]
    sub cl, '0'
    cmp cl, 9
    ja .pd_done
    imul eax, eax, 10
    add eax, ecx
    inc rdi
    jmp .pd_loop
.pd_done:
    ret

; ----------------------------------------------------------------------------
; load_keymap — GetKeyboardMapping for the full keycode range.
; ----------------------------------------------------------------------------
load_keymap:
    push rbx
    push r12
    push r13
    call x11_flush                  ; ensure prior requests sent
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_GET_KEYBOARD_MAPPING
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 2
    mov eax, [min_keycode]
    mov [rdi + 4], al
    mov eax, [max_keycode]
    sub eax, [min_keycode]
    inc eax
    mov [rdi + 5], al               ; count
    mov word [rdi + 6], 0           ; pad
    lea rsi, [tmp_buf]
    mov rdx, 8
    call x11_buffer
    inc dword [x11_seq]
    call x11_flush

    ; Read 32-byte reply header.
    mov rax, SYS_READ
    mov rdi, [x11_fd]
    lea rsi, [tmp_buf]
    mov rdx, 32
    syscall
    cmp rax, 32
    jl .lk_fail
    cmp byte [tmp_buf], 1
    jne .lk_fail
    movzx eax, byte [tmp_buf + 1]
    mov [keysyms_per_keycode], eax
    mov ecx, [tmp_buf + 4]          ; reply length in 4-byte units
    shl ecx, 2                      ; bytes
    mov ebx, ecx                    ; bytes still to drain off the socket
    ; Cap stored bytes at our buffer; everything beyond just gets dropped.
    mov r12d, ecx
    cmp r12d, 32768
    jbe .lk_have_cap
    mov r12d, 32768
.lk_have_cap:
    xor r13d, r13d                  ; bytes stored so far
.lk_drain:
    test ebx, ebx
    jz .lk_done
    mov rax, SYS_READ
    mov rdi, [x11_fd]
    cmp r13d, r12d
    jae .lk_discard
    ; Read into keymap_buf at offset r13.
    lea rsi, [keymap_buf]
    add rsi, r13
    mov edx, r12d
    sub edx, r13d                   ; bytes left in store
    cmp edx, ebx
    jbe .lk_read_store
    mov edx, ebx
.lk_read_store:
    syscall
    test rax, rax
    jle .lk_fail_drain
    add r13d, eax
    sub ebx, eax
    jmp .lk_drain
.lk_discard:
    ; Read overflow into tmp_buf and throw away.
    lea rsi, [tmp_buf]
    mov edx, ebx
    cmp edx, 4096
    jbe .lk_read_drop
    mov edx, 4096
.lk_read_drop:
    syscall
    test rax, rax
    jle .lk_fail_drain
    sub ebx, eax
    jmp .lk_drain
.lk_done:
    ; If the socket drain completed (ebx==0), keep keysyms_per_keycode.
    ; If we hit the cap and dropped overflow, partial keymap still works
    ; for keycodes whose data fit; high-keycode lookups read zero from
    ; BSS and return "no keysym", which keysym_for handles gracefully.
    pop r13
    pop r12
    pop rbx
    ret
.lk_fail_drain:
    ; Some bytes still on the wire. Continue draining best-effort.
    test ebx, ebx
    jz .lk_fail
    jmp .lk_discard
.lk_fail:
    mov dword [keysyms_per_keycode], 0
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; grab_input — XGrabKeyboard + XGrabPointer with retry loop. Returns
; rax = 0 on full success, non-zero on any failure after timeout.
; ----------------------------------------------------------------------------
grab_input:
    push rbx
    push r12
    mov r12d, 50                    ; ~5s with 100ms sleeps
.gi_try:
    ; XGrabKeyboard: opcode=31, owner-events=0, length=4, grab-window,
    ;                time(=CurrentTime), pointer-mode=0(Sync? no — Async=1),
    ;                keyboard-mode=1, pad...
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_GRAB_KEYBOARD
    mov byte [rdi + 1], 1           ; owner-events
    mov word [rdi + 2], 4
    mov eax, [win_id]
    mov [rdi + 4], eax
    mov dword [rdi + 8], 0          ; CurrentTime
    mov byte [rdi + 12], 1          ; pointer-mode = Async
    mov byte [rdi + 13], 1          ; keyboard-mode = Async
    mov word [rdi + 14], 0
    lea rsi, [tmp_buf]
    mov rdx, 16
    call x11_buffer
    inc dword [x11_seq]
    call x11_flush
    ; Read 32-byte reply.
    mov rax, SYS_READ
    mov rdi, [x11_fd]
    lea rsi, [tmp_buf]
    mov rdx, 32
    syscall
    cmp rax, 32
    jl .gi_fail
    cmp byte [tmp_buf], 1           ; reply
    jne .gi_keep_trying
    cmp byte [tmp_buf + 1], 0       ; status: 0 = Success
    je .gi_kbd_ok
.gi_keep_trying:
    test r12d, r12d
    jz .gi_fail
    dec r12d
    ; nanosleep 100ms
    sub rsp, 16
    mov qword [rsp], 0              ; tv_sec
    mov qword [rsp + 8], 100000000  ; tv_nsec
    mov rax, SYS_NANOSLEEP
    mov rdi, rsp
    xor esi, esi
    syscall
    add rsp, 16
    jmp .gi_try
.gi_kbd_ok:
    ; XGrabPointer: opcode=26, owner-events=1, length=6,
    ;   grab-window, event-mask(2), pointer-mode(1), keyboard-mode(1),
    ;   confine-to(4), cursor(4), time(4)
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_GRAB_POINTER
    mov byte [rdi + 1], 1
    mov word [rdi + 2], 6
    mov eax, [win_id]
    mov [rdi + 4], eax
    mov word [rdi + 8], 0           ; event-mask = 0 (we don't want pointer events)
    mov byte [rdi + 10], 1          ; pointer-mode = Async
    mov byte [rdi + 11], 1          ; keyboard-mode = Async
    mov dword [rdi + 12], 0         ; confine-to = None
    mov dword [rdi + 16], 0         ; cursor = None
    mov dword [rdi + 20], 0         ; time = CurrentTime
    lea rsi, [tmp_buf]
    mov rdx, 24
    call x11_buffer
    inc dword [x11_seq]
    call x11_flush
    mov rax, SYS_READ
    mov rdi, [x11_fd]
    lea rsi, [tmp_buf]
    mov rdx, 32
    syscall
    cmp rax, 32
    jl .gi_fail
    cmp byte [tmp_buf], 1
    jne .gi_fail
    cmp byte [tmp_buf + 1], 0
    jne .gi_fail
    xor eax, eax
    pop r12
    pop rbx
    ret
.gi_fail:
    mov rax, 1
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; ungrab_input — release keyboard + pointer.
; ----------------------------------------------------------------------------
ungrab_input:
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_UNGRAB_KEYBOARD
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 2
    mov dword [rdi + 4], 0          ; time = CurrentTime
    lea rsi, [tmp_buf]
    mov rdx, 8
    call x11_buffer
    inc dword [x11_seq]

    lea rdi, [tmp_buf]
    mov byte [rdi], X11_UNGRAB_POINTER
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 2
    mov dword [rdi + 4], 0
    lea rsi, [tmp_buf]
    mov rdx, 8
    call x11_buffer
    inc dword [x11_seq]
    call x11_flush
    ret

; ----------------------------------------------------------------------------
; compose_and_upload_bg — ONE-SHOT path: build a screen-sized BGRX buffer
; in user memory (wallpaper pixels OR solid bg_color), alpha-blend the
; logo on top centred near the top, then upload to a server-side pixmap
; so render_screen can CopyArea it cheaply on every keystroke.
;
; Without this the lock screen is a flat colour with an opaque-square
; logo. With it: the user's wallpaper shows through the logo's
; transparent areas, identical to the offline ImageMagick preview.
;
; Memory: composed_bg = mmap(screen_w * screen_h * 4, anon) — for a 1920
; ×1200 screen that's 9.2 MB user heap. Released implicitly at exit.
; ----------------------------------------------------------------------------
compose_and_upload_bg:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; --- 1. Allocate the composed_bg buffer ---
    movzx eax, word [screen_w]
    movzx ecx, word [screen_h]
    imul eax, ecx
    shl eax, 2                              ; * 4 bytes per BGRX pixel
    mov rsi, rax
    xor edi, edi                            ; addr=0 (kernel chooses)
    mov rdx, PROT_READ | PROT_WRITE
    mov r10d, MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1                              ; fd
    xor r9d, r9d                            ; offset
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js .cu_done                             ; mmap failed → skip composition
    mov [composed_bg_ptr], rax
    mov r12, rax                            ; r12 = composed_bg ptr

    ; --- 2. Fill from wallpaper (RGB → BGRX) or solid bg_color ---
    movzx r13d, word [screen_w]
    movzx r14d, word [screen_h]
    mov eax, r13d
    imul eax, r14d
    mov r15d, eax                           ; total pixels
    cmp qword [bg_addr], 0
    je .cu_solid

    ; Wallpaper path: src 3 bytes (R G B), dst 4 bytes (B G R X).
    mov rsi, [bg_addr]
    mov rdi, r12
    xor ecx, ecx
.cu_wp_loop:
    cmp ecx, r15d
    jge .cu_after_bg
    movzx eax, byte [rsi]                   ; R
    mov [rdi + 2], al
    movzx eax, byte [rsi + 1]               ; G
    mov [rdi + 1], al
    movzx eax, byte [rsi + 2]               ; B
    mov [rdi], al
    mov byte [rdi + 3], 0
    add rsi, 3
    add rdi, 4
    inc ecx
    jmp .cu_wp_loop

.cu_solid:
    mov rdi, r12
    mov eax, [cfg_bg_color]
    and eax, 0x00ffffff                     ; drop alpha for the pixmap
    xor ecx, ecx
.cu_solid_loop:
    cmp ecx, r15d
    jge .cu_after_bg
    mov [rdi], eax
    add rdi, 4
    inc ecx
    jmp .cu_solid_loop
.cu_after_bg:

    ; --- 3. Logo blend skipped: bg image is now a pre-baked flat PNG
    ; that already contains the logo and tagline. The asm side just
    ; blits it. To re-enable logo overlay, restore the alpha-blend
    ; path that follows.
    jmp .cu_skip_logo
    cmp qword [logo_addr], 0
    je .cu_skip_logo
    movzx ebx, word [logo_w]
    test ebx, ebx
    jz .cu_skip_logo
    movzx r14d, word [logo_h]
    test r14d, r14d
    jz .cu_skip_logo
    ; logo_x = (screen_w - logo_w) / 2; logo_y = LOGO_Y_FROM_TOP
    movzx eax, word [screen_w]
    sub eax, ebx
    shr eax, 1
    mov r10d, eax                           ; r10 = logo_x
    mov r11d, LOGO_Y_FROM_TOP               ; r11 = logo_y
    mov r13, [logo_addr]                    ; src RGBA
    movzx r15d, word [screen_w]
    ; for each row in the logo:
    xor ecx, ecx
.cu_lg_row:
    cmp ecx, r14d
    jge .cu_skip_logo
    ; dst row pointer = composed_bg + ((logo_y + row) * screen_w + logo_x) * 4
    mov eax, r11d
    add eax, ecx
    imul eax, r15d
    add eax, r10d
    shl rax, 2
    mov rdi, r12
    add rdi, rax
    ; src row pointer = logo_addr + row * logo_w * 4
    mov eax, ecx
    imul eax, ebx
    shl rax, 2
    mov rsi, r13
    add rsi, rax
    ; per-pixel blend, ebx wide.
    push rcx
    xor edx, edx                            ; col
.cu_lg_px:
    cmp edx, ebx
    jge .cu_lg_row_done
    movzx eax, byte [rsi + 3]               ; alpha
    test eax, eax
    jz .cu_lg_skip                          ; fully transparent → keep bg
    cmp eax, 255
    jne .cu_lg_blend
    ; Fully opaque: just write logo RGB into BGRX dst.
    movzx eax, byte [rsi + 2]               ; B
    mov [rdi], al
    movzx eax, byte [rsi + 1]               ; G
    mov [rdi + 1], al
    movzx eax, byte [rsi]                   ; R
    mov [rdi + 2], al
    mov byte [rdi + 3], 0
    jmp .cu_lg_skip
.cu_lg_blend:
    ; out = (alpha*fg + (255-alpha)*bg + 127) / 255 — per channel.
    ; eax holds alpha for the duration; we don't push/pop it.
    ; B  (dst layout BGRX — dst[0] = blue)
    movzx ecx, byte [rsi + 2]               ; logo B
    mov r8d, eax
    imul r8d, ecx                           ; alpha * fg.B
    movzx ecx, byte [rdi]                   ; bg B
    mov r9d, 255
    sub r9d, eax
    imul r9d, ecx                           ; (255-alpha) * bg.B
    add r8d, r9d
    add r8d, 127
    shr r8d, 8                              ; /256 — close-enough divide
    mov [rdi], r8b
    ; G
    movzx ecx, byte [rsi + 1]
    mov r8d, eax
    imul r8d, ecx
    movzx ecx, byte [rdi + 1]
    mov r9d, 255
    sub r9d, eax
    imul r9d, ecx
    add r8d, r9d
    add r8d, 127
    shr r8d, 8
    mov [rdi + 1], r8b
    ; R  (dst[2] = red)
    movzx ecx, byte [rsi]
    mov r8d, eax
    imul r8d, ecx
    movzx ecx, byte [rdi + 2]
    mov r9d, 255
    sub r9d, eax
    imul r9d, ecx
    add r8d, r9d
    add r8d, 127
    shr r8d, 8
    mov [rdi + 2], r8b
.cu_lg_skip:
    add rdi, 4
    add rsi, 4
    inc edx
    jmp .cu_lg_px
.cu_lg_row_done:
    pop rcx
    inc ecx
    jmp .cu_lg_row
.cu_skip_logo:

    ; --- 4. CreatePixmap and CreateGC for the pixmap ---
    call alloc_xid
    mov [bg_pixmap], eax
    mov ebx, eax
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_CREATE_PIXMAP
    movzx eax, byte [root_depth]
    mov [rdi + 1], al
    mov word [rdi + 2], 4                   ; 4 words
    mov [rdi + 4], ebx                      ; pid
    mov eax, [win_id]
    mov [rdi + 8], eax                      ; drawable (root or any window)
    mov ax, [screen_w]
    mov [rdi + 12], ax
    mov ax, [screen_h]
    mov [rdi + 14], ax
    lea rsi, [tmp_buf]
    mov rdx, 16
    call x11_buffer
    inc dword [x11_seq]

    ; GC for the pixmap.
    call alloc_xid
    mov [gc_pix], eax
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_CREATE_GC
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 4                   ; 4 words, no values
    mov [rdi + 4], eax
    mov eax, [bg_pixmap]
    mov [rdi + 8], eax
    mov dword [rdi + 12], 0                 ; value-mask = 0
    lea rsi, [tmp_buf]
    mov rdx, 16
    call x11_buffer
    inc dword [x11_seq]

    ; --- 5. Chunked PutImage from composed_bg into bg_pixmap ---
    ; Max bytes per request body (X11 without BIG-REQUESTS): 65535 words
    ; = 262140 bytes. Subtract the 24-byte header → 262116 bytes = up to
    ; 34 rows on a 1920-wide screen. We use 30 rows per chunk for safety.
    ; Each chunk: copy bytes into x11_write_buf via x11_buffer.
    movzx r13d, word [screen_w]              ; w
    movzx r14d, word [screen_h]              ; h
    mov r15, [composed_bg_ptr]
    xor ebx, ebx                             ; current y row
.cu_chunk:
    cmp ebx, r14d
    jge .cu_done
    mov ecx, 30                              ; rows per chunk
    mov eax, r14d
    sub eax, ebx
    cmp ecx, eax
    jbe .cu_chunk_h_ok
    mov ecx, eax
.cu_chunk_h_ok:
    ; chunk height = ecx. Per-chunk byte count = w * h * 4.
    mov eax, r13d
    imul eax, ecx
    shl eax, 2                               ; data bytes
    push rax                                 ; save data bytes
    push rcx                                 ; save chunk_h
    ; Copy data into put_image_buf+24.
    mov edx, eax                             ; bytes to copy
    mov rsi, r15                             ; src = composed_bg + offset
    lea rdi, [put_image_buf + 24]
    push rcx
    mov rcx, rdx
    rep movsb
    pop rcx
    add r15, rdx                             ; advance src ptr
    ; Build PutImage header.
    pop rcx
    pop rax
    push rax
    push rcx
    lea rdi, [put_image_buf]
    mov byte [rdi], X11_PUT_IMAGE
    mov byte [rdi + 1], 2                    ; format = ZPixmap
    mov edx, eax                             ; data bytes
    add edx, 3
    shr edx, 2
    add edx, 6                               ; + 6 fixed words
    mov [rdi + 2], dx
    mov eax, [bg_pixmap]
    mov [rdi + 4], eax                       ; drawable
    mov eax, [gc_pix]
    mov [rdi + 8], eax                       ; gc
    mov [rdi + 12], r13w                     ; width
    mov [rdi + 14], cx                       ; chunk height
    mov word [rdi + 16], 0                   ; dst-x
    mov [rdi + 18], bx                       ; dst-y = current row
    mov byte [rdi + 20], 0                   ; left-pad
    movzx eax, byte [root_depth]
    mov [rdi + 21], al
    mov word [rdi + 22], 0
    pop rcx
    pop rax
    mov rdx, rax
    add rdx, 24                              ; + header
    add rdx, 3
    and rdx, ~3
    ; The chunk is far bigger than x11_write_buf (32 KB). Flush any
    ; pending small writes first, then SYS_WRITE the chunk directly to
    ; the X11 fd. x11_buffer would overflow its BSS buffer here.
    push rcx
    push rdx
    push rax
    call x11_flush
    pop rax
    pop rdx
    pop rcx
    push rcx
    mov rax, SYS_WRITE
    mov rdi, [x11_fd]
    lea rsi, [put_image_buf]
    syscall
    pop rcx
    inc dword [x11_seq]
    add ebx, ecx
    jmp .cu_chunk

.cu_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; render_screen — paint background, logo, tagline, dot indicator. Called
; on Expose, on keystroke (dot count change), and on auth failure flash.
; ----------------------------------------------------------------------------
render_screen:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; --- background ---
    ; If we have a composed bg pixmap, CopyArea it onto the window
    ; (server-side, fast). Otherwise fall back to a solid colour fill.
    cmp dword [bg_pixmap], 0
    je .rs_solid_fill
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_COPY_AREA
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 7
    mov eax, [bg_pixmap]
    mov [rdi + 4], eax              ; src
    mov eax, [win_id]
    mov [rdi + 8], eax              ; dst
    mov eax, [gc_bg]
    mov [rdi + 12], eax             ; gc
    mov word [rdi + 16], 0          ; src-x
    mov word [rdi + 18], 0          ; src-y
    mov word [rdi + 20], 0          ; dst-x
    mov word [rdi + 22], 0          ; dst-y
    mov ax, [screen_w]
    mov [rdi + 24], ax
    mov ax, [screen_h]
    mov [rdi + 26], ax
    lea rsi, [tmp_buf]
    mov rdx, 28
    call x11_buffer
    inc dword [x11_seq]
    jmp .rs_after_bg
.rs_solid_fill:
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_POLY_FILL_RECT
    mov byte [rdi + 1], 0
    mov word [rdi + 2], 5
    mov eax, [win_id]
    mov [rdi + 4], eax
    mov eax, [gc_bg]
    mov [rdi + 8], eax
    mov word [rdi + 12], 0
    mov word [rdi + 14], 0
    mov ax, [screen_w]
    mov [rdi + 16], ax
    mov ax, [screen_h]
    mov [rdi + 18], ax
    lea rsi, [tmp_buf]
    mov rdx, 20
    call x11_buffer
    inc dword [x11_seq]
.rs_after_bg:
    ; Logo is already baked into bg_pixmap by compose_and_upload_bg, so
    ; we skip the per-frame PutImage path. If we didn't get a pixmap
    ; (mmap or X11 failure) and we still have a logo, render it directly.
    cmp dword [bg_pixmap], 0
    jne .rs_after_logo
    cmp qword [logo_addr], 0
    je .rs_after_logo
    movzx r12d, word [logo_w]
    movzx r13d, word [logo_h]
    test r12d, r12d
    jz .rs_after_logo
    movzx eax, word [screen_w]
    sub eax, r12d
    shr eax, 1
    mov r14d, eax
    mov r15d, LOGO_Y_FROM_TOP
    mov edi, r12d
    mov esi, r13d
    mov edx, r14d
    mov ecx, r15d
    mov r8, [logo_addr]
    call put_image_rgba
.rs_after_logo:

    ; --- tagline ---
    ; Skipped: tagline is baked into the flat bg PNG. Keep this label
    ; in place for callers that still jump to it.
    jmp .rs_after_tagline
    lea rdi, [cfg_tagline]
    call str_len
    test eax, eax
    jz .rs_after_tagline
    mov r12d, eax                   ; text length
    cmp r12d, 254
    jbe .rs_t_len_ok
    mov r12d, 254
.rs_t_len_ok:
    ; Rough centre: assume ~10px per char with the default fixed font.
    ; Real text-extents would need a sync round-trip; v0.1 is good
    ; enough since the user picks the tagline.
    movzx eax, word [screen_w]
    mov ecx, r12d
    imul ecx, 10
    sub eax, ecx
    shr eax, 1
    mov r13d, eax                   ; x
    mov r14d, LOGO_Y_FROM_TOP
    add r14d, 96
    add r14d, 40                    ; tagline y below logo
    ; PolyText8: opcode=74, length, drawable, gc, x(2), y(2), [text-elt...]
    ; text-elt = [length(1), delta(1), string(length)]
    ; length, delta, string is part of the request payload after fixed.
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_POLY_TEXT_8
    mov byte [rdi + 1], 0
    ; total length in 4-byte words = (4 + 4 + 4 + 4 + 2 + textlen + 3) / 4
    mov eax, r12d
    add eax, 2                      ; length+delta bytes
    add eax, 3
    shr eax, 2
    add eax, 4                      ; 4 fixed words
    mov [rdi + 2], ax
    mov eax, [win_id]
    mov [rdi + 4], eax
    mov eax, [gc_text]
    mov [rdi + 8], eax
    mov [rdi + 12], r13w
    mov [rdi + 14], r14w
    mov [rdi + 16], r12b            ; element length
    mov byte [rdi + 17], 0          ; delta
    ; copy string
    lea rsi, [cfg_tagline]
    lea r10, [rdi + 18]
    xor ecx, ecx
.rs_t_cp:
    cmp ecx, r12d
    jge .rs_t_pad
    movzx eax, byte [rsi + rcx]
    mov [r10 + rcx], al
    inc ecx
    jmp .rs_t_cp
.rs_t_pad:
    mov eax, r12d
    add eax, 18
    add eax, 3
    and eax, ~3
    mov rdx, rax
    lea rsi, [tmp_buf]
    call x11_buffer
    inc dword [x11_seq]
.rs_after_tagline:

    ; --- dots ---
    mov rax, [password_len]
    cmp rax, 32
    jbe .rs_d_lenok
    mov rax, 32
.rs_d_lenok:
    test rax, rax
    jz .rs_done
    mov r12, rax                    ; n dots
    ; Total width = n * (2*radius) + (n-1) * gap
    mov rax, r12
    imul rax, DOT_RADIUS * 2
    mov rcx, r12
    dec rcx
    imul rcx, DOT_GAP
    add rax, rcx
    movzx ecx, word [screen_w]
    sub ecx, eax
    shr ecx, 1                      ; left x
    mov r13d, ecx
    movzx ecx, word [screen_h]
    shr ecx, 1                      ; centre y
    mov r14d, ecx
    ; Build PolyFillRectangle with n rectangles.
    lea rdi, [tmp_buf]
    mov byte [rdi], X11_POLY_FILL_RECT
    mov byte [rdi + 1], 0
    mov rax, r12
    shl rax, 1                      ; rectangles × 2 words
    add rax, 3                      ; + 3 fixed words
    mov [rdi + 2], ax
    mov eax, [win_id]
    mov [rdi + 4], eax
    mov eax, [gc_fg]
    mov [rdi + 8], eax
    lea r15, [rdi + 12]
    xor ecx, ecx
.rs_d_loop:
    cmp rcx, r12
    jge .rs_d_send
    mov eax, ecx
    imul eax, DOT_RADIUS * 2 + DOT_GAP
    add eax, r13d                   ; x
    mov [r15], ax
    mov eax, r14d
    sub eax, DOT_RADIUS
    mov [r15 + 2], ax
    mov word [r15 + 4], DOT_RADIUS * 2
    mov word [r15 + 6], DOT_RADIUS * 2
    add r15, 8
    inc rcx
    jmp .rs_d_loop
.rs_d_send:
    mov rax, r12
    shl rax, 3
    add rax, 12
    mov rdx, rax
    lea rsi, [tmp_buf]
    call x11_buffer
    inc dword [x11_seq]
.rs_done:
    call x11_flush
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; put_image_rgba — edi=w, esi=h, edx=dst_x, ecx=dst_y, r8=src.
; Sends PutImage(format=ZPixmap=2, depth=24) for the full image.
; The src layout is RGBA; X11 ZPixmap on a 24-bit visual wants BGRX
; (for little-endian image-byte-order=LSBFirst). We swap on the fly into
; tmp_buf before sending.
; ----------------------------------------------------------------------------
put_image_rgba:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d, edi                   ; w
    mov r13d, esi                   ; h
    mov r14d, edx                   ; dst-x
    mov r15d, ecx                   ; dst-y
    mov rbx, r8                     ; src
    ; Compute byte count = w * h * 4
    mov eax, r12d
    imul eax, r13d
    shl eax, 2
    cmp eax, 200000
    ja .pir_done                    ; v0.1 hard cap; needs BIG-REQ split otherwise
    mov ecx, eax                    ; total bytes
    ; Convert src RGBA → BGRA in put_image_buf+24 (header is 24 bytes).
    lea rdi, [put_image_buf + 24]
    xor edx, edx
.pir_swap:
    cmp edx, ecx
    jge .pir_send
    movzx eax, byte [rbx + rdx + 2] ; B
    mov [rdi + rdx], al
    movzx eax, byte [rbx + rdx + 1] ; G
    mov [rdi + rdx + 1], al
    movzx eax, byte [rbx + rdx]     ; R
    mov [rdi + rdx + 2], al
    movzx eax, byte [rbx + rdx + 3] ; A → store as X (server ignores on 24-bit)
    mov [rdi + rdx + 3], al
    add edx, 4
    jmp .pir_swap
.pir_send:
    ; Build header.
    lea rdi, [put_image_buf]
    mov byte [rdi], X11_PUT_IMAGE
    mov byte [rdi + 1], 2           ; format = ZPixmap
    mov eax, ecx
    add eax, 3
    shr eax, 2
    add eax, 6                      ; 6 fixed words
    mov [rdi + 2], ax
    mov eax, [win_id]
    mov [rdi + 4], eax              ; drawable
    mov eax, [gc_fg]
    mov [rdi + 8], eax              ; gc
    mov [rdi + 12], r12w            ; width
    mov [rdi + 14], r13w            ; height
    mov [rdi + 16], r14w            ; dst-x
    mov [rdi + 18], r15w            ; dst-y
    mov byte [rdi + 20], 0          ; left-pad
    movzx eax, byte [root_depth]
    mov [rdi + 21], al
    mov word [rdi + 22], 0
    mov rdx, rcx
    add rdx, 24
    add rdx, 3
    and rdx, ~3
    lea rsi, [put_image_buf]
    call x11_buffer
    inc dword [x11_seq]
.pir_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; ----------------------------------------------------------------------------
; fp_start — fork + exec /usr/bin/fprintd-verify so a fingerprint touch
; can unlock the screen without the user typing a password. Returns
; with fp_pid + fp_pipe_rd populated, or zeroed if anything went wrong
; (no fprintd installed, fork failed, etc.). The lock screen still
; works in that case — we just rely on the password path.
;
; The child's stdout/stderr go into a pipe we own; we don't actually
; read the bytes (fprintd-verify prints chatty status), but EOF on
; read tells us the child exited so the event loop can waitpid+check
; the exit code without busy-waiting.
; ----------------------------------------------------------------------------
fp_start:
    push rbx
    push r12
    push r13
    ; pipe(2)
    sub rsp, 16
    mov rax, SYS_PIPE
    mov rdi, rsp
    syscall
    test rax, rax
    js .fp_fail_sp
    mov ebx, [rsp]                      ; read end (parent keeps)
    mov r12d, [rsp + 4]                 ; write end (goes to child)
    add rsp, 16

    mov rax, SYS_FORK
    syscall
    test rax, rax
    js .fp_fail_pipes
    jnz .fp_parent

    ; --- child ---
    ; dup2(write_end, 1) and dup2(write_end, 2) so fprintd-verify's
    ; chatter goes into our pipe; close stdin (open /dev/null over
    ; fd 0 so the child has a valid stdin if it reads).
    mov rax, SYS_DUP2
    mov edi, r12d
    mov esi, 1
    syscall
    mov rax, SYS_DUP2
    mov edi, r12d
    mov esi, 2
    syscall
    mov rax, SYS_CLOSE
    mov edi, ebx
    syscall
    mov rax, SYS_CLOSE
    mov edi, r12d
    syscall
    ; Replace stdin with /dev/null.
    mov rax, SYS_OPEN
    lea rdi, [devnull_path]
    xor esi, esi                        ; O_RDONLY
    syscall
    test rax, rax
    js .fp_child_skip_stdin
    mov r13, rax
    mov rax, SYS_DUP2
    mov edi, r13d
    xor esi, esi
    syscall
    mov rax, SYS_CLOSE
    mov edi, r13d
    syscall
.fp_child_skip_stdin:
    mov rax, SYS_EXECVE
    lea rdi, [fp_path]
    lea rsi, [fp_argv]
    mov rdx, [envp]
    syscall
    ; exec failed (fprintd-verify not installed) — die quietly so
    ; bolt doesn't fall over.
    mov rax, SYS_EXIT
    mov edi, 127
    syscall

.fp_parent:
    mov [fp_pid], eax                   ; save child pid
    mov [fp_pipe_rd], ebx               ; pipe read end
    mov byte [fp_active], 1
    ; close write end in parent
    mov rax, SYS_CLOSE
    mov edi, r12d
    syscall
    ; Set the read end non-blocking so the drain loop in fp_check_exit
    ; can't wedge on a child that's alive but not currently writing.
    ; Without this, fprintd-verify prints status messages periodically;
    ; we wake on POLLIN, drain what's there, then read() blocks again
    ; until the next chatter or until the child exits — which means
    ; bolt never reaps the zombie and the user never gets a respawn.
    mov rax, SYS_FCNTL
    mov edi, ebx
    mov esi, F_SETFL
    mov edx, O_NONBLOCK
    syscall
    pop r13
    pop r12
    pop rbx
    ret

.fp_fail_sp:
    add rsp, 16
.fp_fail_pipes:
    mov dword [fp_pid], 0
    mov dword [fp_pipe_rd], 0
    mov byte [fp_active], 0
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; fp_stop — best-effort cleanup: kill the fp child if it's still alive,
; reap, close pipe. Called on unlock and on auth-failure restart paths.
; ----------------------------------------------------------------------------
fp_stop:
    cmp byte [fp_active], 0
    je .fps_done
    mov byte [fp_active], 0
    ; SIGTERM (15) the child if pid > 0
    mov eax, dword [fp_pid]
    test eax, eax
    jz .fps_close_pipe
    mov rax, SYS_KILL
    mov edi, [fp_pid]
    mov esi, 15
    syscall
    ; reap (blocking — child should exit fast on SIGTERM)
    sub rsp, 16
    mov rax, SYS_WAIT4
    mov edi, [fp_pid]
    mov rsi, rsp
    xor edx, edx
    xor r10d, r10d
    syscall
    add rsp, 16
.fps_close_pipe:
    mov eax, [fp_pipe_rd]
    test eax, eax
    jz .fps_zero
    mov rax, SYS_CLOSE
    mov edi, [fp_pipe_rd]
    syscall
.fps_zero:
    mov dword [fp_pid], 0
    mov dword [fp_pipe_rd], 0
.fps_done:
    ret

; ----------------------------------------------------------------------------
; fp_check_exit — if the fp child has exited and matched (status 0),
; return rax=1 (caller should unlock). Status non-zero (rejection,
; SIGTERM, no enrolment) → rax=0 and fp_active flips off so the event
; loop stops polling that pipe.
;
; Called when poll() reports POLLIN/POLLHUP on fp_pipe_rd. Drains any
; pending bytes (fprintd-verify chatter) before checking exit so a
; final flush from the child doesn't wedge poll on the next iteration.
; ----------------------------------------------------------------------------
fp_check_exit:
    cmp byte [fp_active], 0
    je .fpc_zero
    ; Drain remaining pipe bytes into tmp_buf. Pipe is non-blocking
    ; (set in fp_start) so read returns -EAGAIN once the buffer is
    ; empty even if the child is still alive.
.fpc_drain:
    mov rax, SYS_READ
    mov edi, [fp_pipe_rd]
    lea rsi, [tmp_buf]
    mov rdx, 4096
    syscall
    cmp rax, 0
    jg .fpc_drain                       ; got bytes, keep going
    ; rax == 0 → EOF (child closed pipe). rax < 0 → EAGAIN or error.
    ; Use wait4 with WNOHANG to find out whether the child has actually
    ; exited; if it hasn't, just return 0 and let the next poll cycle
    ; deliver the next batch of bytes / the eventual EOF.
    sub rsp, 16
    mov rax, SYS_WAIT4
    mov edi, [fp_pid]
    mov rsi, rsp
    mov edx, WNOHANG
    xor r10d, r10d
    syscall
    test eax, eax
    jz .fpc_alive_sp                    ; rax==0 → child still alive
    js .fpc_after_wait_fail             ; -1 → wait error
    mov ecx, [rsp]                      ; wstatus
    add rsp, 16
    ; Mark inactive regardless of outcome — we just reaped it.
    mov byte [fp_active], 0
    ; Close pipe and zero pid so subsequent fp_stop calls are no-ops.
    mov eax, [fp_pipe_rd]
    test eax, eax
    jz .fpc_after_close
    mov rax, SYS_CLOSE
    mov edi, [fp_pipe_rd]
    syscall
.fpc_after_close:
    mov dword [fp_pid], 0
    mov dword [fp_pipe_rd], 0
    ; wstatus & 0xff == 0 means normal exit; high byte is exit code.
    ; fprintd-verify is a one-shot: it waits ~10s for a touch then
    ; exits 1 with "verify-no-match" if nothing arrived. To keep the
    ; reader armed for the entire lock duration we respawn the child
    ; on any non-match exit; the user gets continuous fingerprint
    ; coverage instead of a 10-second window at lock-start.
    test ecx, 0x7f
    jnz .fpc_respawn                    ; signaled — likely system shutdown,
                                        ; respawn anyway (fp_start tolerates it)
    shr ecx, 8
    test ecx, ecx
    jnz .fpc_respawn                    ; non-zero exit → no match yet
    mov eax, 1                          ; status 0 → matched, unlock
    ret
.fpc_respawn:
    call fp_start                       ; relaunch fprintd-verify
    xor eax, eax
    ret
.fpc_alive_sp:
    add rsp, 16
    xor eax, eax
    ret
.fpc_after_wait_fail:
    add rsp, 16
    mov byte [fp_active], 0
.fpc_zero:
    xor eax, eax
    ret

; ----------------------------------------------------------------------------
; event_loop — read events, dispatch on type. Returns when password
; verification succeeds.
; ----------------------------------------------------------------------------
event_loop:
.el_top:
    call x11_flush
    ; Build a pollfd array on the stack:
    ;   slot 0: x11_fd, POLLIN
    ;   slot 1: fp_pipe_rd, POLLIN  (only included while fp_active)
    sub rsp, 16
    mov eax, [x11_fd]
    mov [rsp], eax
    mov word [rsp + 4], 1                 ; POLLIN
    mov word [rsp + 6], 0
    mov esi, 1                            ; nfds (start with X11 only)
    cmp byte [fp_active], 0
    je .el_poll_call
    mov eax, [fp_pipe_rd]
    mov [rsp + 8], eax
    mov word [rsp + 12], 1                ; POLLIN
    mov word [rsp + 14], 0
    mov esi, 2                            ; nfds (X11 + fp pipe)
.el_poll_call:
    mov rax, SYS_POLL
    lea rdi, [rsp]
    mov edx, -1                           ; block indefinitely
    syscall
    ; Inspect revents BEFORE dropping the stack frame.
    test rax, rax
    js .el_poll_done                      ; signal/error — restart loop
    movzx ecx, word [rsp + 6]             ; X11 revents
    movzx r8d, word [rsp + 14]            ; fp pipe revents
.el_poll_done:
    add rsp, 16
    test r8d, r8d
    jz .el_after_fp
    ; Pipe wakeup: child wrote bytes or exited. Drain + check status.
    call fp_check_exit
    test eax, eax
    jnz .el_unlock                        ; fingerprint matched
.el_after_fp:
    test ecx, ecx
    jz .el_top                            ; nothing on X11 yet
    ; Read one X11 event.
    mov rax, SYS_READ
    mov rdi, [x11_fd]
    lea rsi, [ev_buf]
    mov rdx, 32
    syscall
    cmp rax, 32
    jl .el_top                       ; transient — retry
    movzx eax, byte [ev_buf]
    and eax, 0x7F                    ; strip send_event flag
    cmp al, EV_KEY_PRESS
    je .el_keypress
    cmp al, EV_EXPOSE
    je .el_expose
    cmp al, EV_MAP_NOTIFY
    je .el_remap
    cmp al, EV_CONFIGURE_NOTIFY
    je .el_top
    jmp .el_top
.el_expose:
    call render_screen
    jmp .el_top
.el_remap:
    ; A new window mapped over us — re-grab to be safe and re-render.
    call render_screen
    jmp .el_top
.el_keypress:
    movzx eax, byte [ev_buf + 1]    ; keycode
    movzx ecx, word [ev_buf + 28]   ; state
    call keysym_for                 ; → eax = keysym, edx = ascii or special
    test edx, edx
    jz .el_top                      ; non-printable, no special — ignore
    cmp edx, 0xFF1B                 ; Escape — clear password
    je .el_clear
    cmp edx, 0xFF08                 ; Backspace
    je .el_backspace
    cmp edx, 0xFF0D                 ; Return
    je .el_enter
    cmp edx, 0xFF8D                 ; KP_Enter
    je .el_enter
    cmp edx, 0xFF                   ; Latin-1 max
    ja .el_top                      ; non-Latin keysym, ignore
    ; Append byte if buffer has room.
    mov rcx, [password_len]
    cmp rcx, MAX_PASSWORD_LEN - 1
    jge .el_top
    mov [password_buf + rcx], dl
    inc qword [password_len]
    call render_screen
    jmp .el_top
.el_clear:
    ; Zero password, redraw with no dots.
    mov rcx, [password_len]
    test rcx, rcx
    jz .el_top
    mov qword [password_len], 0
    lea rdi, [password_buf]
    xor eax, eax
.el_zloop:
    test rcx, rcx
    jz .el_zdone
    mov [rdi], al
    inc rdi
    dec rcx
    jmp .el_zloop
.el_zdone:
    call render_screen
    jmp .el_top
.el_backspace:
    mov rcx, [password_len]
    test rcx, rcx
    jz .el_top
    dec rcx
    mov byte [password_buf + rcx], 0
    mov [password_len], rcx
    call render_screen
    jmp .el_top
.el_enter:
    call do_auth
    test rax, rax
    jz .el_unlock
    ; Wrong password — wipe buffer, redraw.
    mov rcx, [password_len]
    mov qword [password_len], 0
    lea rdi, [password_buf]
    xor eax, eax
.el_eloop:
    test rcx, rcx
    jz .el_edone
    mov [rdi], al
    inc rdi
    dec rcx
    jmp .el_eloop
.el_edone:
    ; Briefly flash the GC fg colour to red, render, restore. v0.1
    ; just renders empty so the user knows the password was rejected.
    call render_screen
    jmp .el_top
.el_unlock:
    ret

; ----------------------------------------------------------------------------
; keysym_for — eax=keycode, ecx=state. Returns:
;   eax = full keysym
;   edx = matching Latin-1 byte (0..255) for the printable / known specials
;         or 0 if neither.
; Looks up in keymap_buf using state bit 0 (Shift) to choose column.
; ----------------------------------------------------------------------------
keysym_for:
    push rbx
    sub eax, [min_keycode]
    test eax, eax
    js .ks_zero
    cmp eax, [max_keycode]
    jg .ks_zero
    ; offset = (keycode - min) * keysyms_per_keycode + (shift ? 1 : 0)
    mov ebx, eax
    imul ebx, [keysyms_per_keycode]
    test ecx, 1                     ; Shift?
    jz .ks_no_shift
    cmp dword [keysyms_per_keycode], 1
    jbe .ks_no_shift
    inc ebx
.ks_no_shift:
    mov eax, [keymap_buf + rbx*4]
    mov edx, eax
    test edx, edx
    jz .ks_zero
    cmp edx, 0xff00
    jb .ks_print                    ; Latin-1 keysym
    ; Special keys we care about: Escape, Backspace, Return, KP_Enter, Delete
    cmp edx, 0xFF1B
    je .ks_done
    cmp edx, 0xFF08
    je .ks_done
    cmp edx, 0xFF0D
    je .ks_done
    cmp edx, 0xFF8D
    je .ks_done
    cmp edx, 0xFFFF
    je .ks_done
    xor edx, edx
    jmp .ks_done
.ks_print:
    and edx, 0xFF
.ks_done:
    pop rbx
    ret
.ks_zero:
    xor eax, eax
    xor edx, edx
    pop rbx
    ret

; ----------------------------------------------------------------------------
; do_auth — fork, exec /usr/local/bin/bolt-auth with password on stdin.
; Returns rax = 0 on auth success, non-zero on failure.
; ----------------------------------------------------------------------------
do_auth:
    push rbx
    push r12
    push r13
    ; pipe(2)
    sub rsp, 16
    mov rax, SYS_PIPE
    mov rdi, rsp
    syscall
    test rax, rax
    js .da_fail_sp
    mov ebx, [rsp]                  ; read end (parent gives to child)
    mov r12d, [rsp + 4]             ; write end (parent writes pw here)
    add rsp, 16

    mov rax, SYS_FORK
    syscall
    test rax, rax
    jl .da_fail
    jnz .da_parent

    ; --- child ---
    ; dup2(read end, 0)
    mov rax, SYS_DUP2
    mov edi, ebx
    xor esi, esi
    syscall
    ; close pipe fds
    mov rax, SYS_CLOSE
    mov edi, ebx
    syscall
    mov rax, SYS_CLOSE
    mov edi, r12d
    syscall
    ; execve /usr/local/bin/bolt-auth, no env (helper rebuilds context).
    mov rax, SYS_EXECVE
    lea rdi, [bolt_auth_path]
    lea rsi, [bolt_auth_argv]
    mov rdx, [envp]
    syscall
    ; exec failed.
    mov rax, SYS_EXIT
    mov edi, 127
    syscall

.da_parent:
    mov r13, rax                    ; child pid
    ; close read end
    mov rax, SYS_CLOSE
    mov edi, ebx
    syscall
    ; write password
    mov rcx, [password_len]
    test rcx, rcx
    jz .da_close_w
    mov rax, SYS_WRITE
    mov edi, r12d
    lea rsi, [password_buf]
    mov rdx, rcx
    syscall
.da_close_w:
    mov rax, SYS_CLOSE
    mov edi, r12d
    syscall
    ; Zero password buffer ASAP.
    mov rcx, [password_len]
    lea rdi, [password_buf]
    xor eax, eax
.da_zero:
    test rcx, rcx
    jz .da_zero_done
    mov [rdi], al
    inc rdi
    dec rcx
    jmp .da_zero
.da_zero_done:
    mov qword [password_len], 0
    ; wait4(child)
    sub rsp, 16
    mov rax, SYS_WAIT4
    mov rdi, r13
    mov rsi, rsp
    xor edx, edx
    xor r10d, r10d
    syscall
    mov eax, [rsp]                  ; wstatus
    add rsp, 16
    test eax, eax                   ; child exited 0 = wstatus & 0xff = 0
    jnz .da_fail
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.da_fail_sp:
    add rsp, 16
.da_fail:
    mov rax, 1
    pop r13
    pop r12
    pop rbx
    ret
