; ============================================================================
; bolt-greet — pure x86_64 asm graphical greeter (session chooser) for the
; CHasm suite. No libc, no X11, single static ELF. Runs on a bare VT via
; DRM/KMS (frame's modeset path) + evdev, draws the ~/.framebg wallpaper with
; a session menu, and on selection releases DRM and runs greet-session with
; the chosen session. When the session exits it re-inits DRM and shows the
; menu again — the login gate that replaces gdm.
;
;   Sessions:  1) tile on frame   2) tile on X   3) i3 on X (safeguard)
;   Actions :  s) suspend         p) power off
;   Shows   :  clock, date, battery
;
; DRM ioctl sequences + connector/mode discovery are lifted from frame.asm's
; proven do_modeset path. Font is Lat15-Fixed16 (X11 misc-fixed, public
; domain), baked in via greetfont.inc.
;
; Build:  nasm -f elf64 bolt-greet.asm -o bolt-greet.o && ld bolt-greet.o -o bolt-greet
; Test :  ./bolt-greet --fbtest   (anon 1920x1200 buffer, render one frame to
;                                  /tmp/greet_fb.raw, exit — no root needed)
; Run  :  sudo ./bolt-greet       (from a text VT with gdm stopped)
; ============================================================================

; ---- syscalls -------------------------------------------------------------
%define SYS_READ          0
%define SYS_WRITE         1
%define SYS_OPEN          2
%define SYS_CLOSE         3
%define SYS_POLL          7
%define SYS_LSEEK         8
%define SYS_MMAP          9
%define SYS_MUNMAP        11
%define SYS_IOCTL         16
%define SYS_NANOSLEEP     35
%define SYS_FORK          57
%define SYS_EXECVE        59
%define SYS_EXIT          60
%define SYS_WAIT4         61
%define SYS_RT_SIGACTION  13
%define SYS_FLOCK         73
%define SYS_FCNTL         72
%define VT_ACTIVATE       0x5606
%define VT_WAITACTIVE     0x5607
%define SYS_RT_SIGRETURN  15
%define SA_RESTORER       0x04000000
%define SYS_TIME          201

%define O_RDONLY          0
%define O_WRONLY          1
%define O_RDWR            0x2
%define O_CREAT           0x40
%define O_TRUNC           0x200
%define O_NONBLOCK        0x800

%define PROT_RW           3
%define MAP_SHARED        1
%define MAP_PRIVATE       2
%define MAP_ANONYMOUS     0x20

; ---- DRM ioctls (lifted from frame.asm) -----------------------------------
%define DRM_IOCTL_SET_MASTER           0x0000641E
%define DRM_IOCTL_DROP_MASTER          0x0000641F
%define DRM_IOCTL_MODE_GETRESOURCES    0xC04064A0
%define DRM_IOCTL_MODE_GETCRTC         0xC06864A1
%define DRM_IOCTL_MODE_SETCRTC         0xC06864A2
%define DRM_IOCTL_MODE_GETENCODER      0xC01464A6
%define DRM_IOCTL_MODE_GETCONNECTOR    0xC05064A7
%define DRM_IOCTL_MODE_ADDFB           0xC01C64AE
%define DRM_IOCTL_MODE_RMFB            0xC00464AF
%define DRM_IOCTL_MODE_CREATE_DUMB     0xC02064B2
%define DRM_IOCTL_MODE_MAP_DUMB        0xC01064B3
%define DRM_IOCTL_MODE_DESTROY_DUMB    0xC00464B4
%define DRM_IOCTL_MODE_PAGE_FLIP       0xC01864B0
%define DRM_MODE_PAGE_FLIP_EVENT       0x01

%define DRM_MODE_CONNECTED   1
%define DRM_MODE_INFO_SIZE   68
%define DRM_MAX_MODES        64
%define DRM_MAX_PROPS        64
%define DRM_MAX_IDS          32

; ---- evdev ----------------------------------------------------------------
%define INPUT_DEV_MAX   32
%define MAX_INPUTS      16
%define EV_KEY          1
; keycodes (linux/input-event-codes.h)
%define KEY_ESC     1
%define KEY_1       2
%define KEY_2       3
%define KEY_3       4
%define KEY_P       25
%define KEY_S       31

; ---- layout / colours (memory dwords are X,R,G,B little-endian = B,G,R,X) --
; Strip-like top info bar + session selector across the bottom; the
; wallpaper stays unobstructed in between.
%define TOPBAR_H    40
%define BOTBAR_H    64
%define COL_ACCENT  0x00E8890F      ; warm orange
%define COL_TEXT    0x00EAEAEA
%define COL_DIM     0x00909090
%define COL_SELTEXT 0x00101010      ; text on the accent bar
%define COL_BG      0x00101418      ; bar fill + fallback bg if no wallpaper

section .rodata
%include "greetfont.inc"            ; greet_font: 95 glyphs, ASCII 32..126, 8x16

str_title:      db "CHasm", 0
str_row0:       db "1  tile on frame", 0
str_row1:       db "2  tile on X", 0
str_row2:       db "3  i3 on X", 0
str_hints:      db "[s] suspend   [p] power off   [Esc] console", 0
str_sep:        db "   ", 0
str_bat:        db "BAT ", 0
str_pctsp:      db "% ", 0
str_nobat:      db "AC", 0
str_chg:        db "chg", 0
str_dis:        db "bat", 0
str_full:       db "full", 0

wday_names:     db "Thu",0, "Fri",0, "Sat",0, "Sun",0, "Mon",0, "Tue",0, "Wed",0
                ; indexed by (days_since_epoch % 7): 1970-01-01 was a Thursday
mon_names:      db "Jan",0, "Feb",0, "Mar",0, "Apr",0, "May",0, "Jun",0
                db "Jul",0, "Aug",0, "Sep",0, "Oct",0, "Nov",0, "Dec",0

path_framebg:   db "/home/geir/.framebg", 0
input_dev_pre:  db "/dev/input/event", 0
path_bat0_cap:  db "/sys/class/power_supply/BAT0/capacity", 0
path_bat0_stat: db "/sys/class/power_supply/BAT0/status", 0
path_bat1_cap:  db "/sys/class/power_supply/BAT1/capacity", 0
path_bat1_stat: db "/sys/class/power_supply/BAT1/status", 0
path_fbtest_out: db "/tmp/greet_fb.raw", 0

; children
path_systemctl: db "/usr/bin/systemctl", 0
path_greetsess: db "/usr/local/bin/greet-session", 0
arg_sysctl0:    db "systemctl", 0
arg_suspend:    db "suspend", 0
arg_poweroff:   db "poweroff", 0
argv_suspend:   dq arg_sysctl0, arg_suspend, 0
argv_poweroff:  dq arg_sysctl0, arg_poweroff, 0
arg_gs0:        db "greet-session", 0
gs_choice1:     db "1", 0
gs_choice2:     db "2", 0
gs_choice3:     db "3", 0
env_path:       db "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 0
env_home:       db "HOME=/root", 0
env_term:       db "TERM=linux", 0
env_mark:       db "GREET_SESSION=1", 0    ; stray-sweep marker: everything a
                                           ; session spawns inherits it; the
                                           ; wrapper kills carriers at startup
child_envp:     dq env_path, env_home, env_term, env_mark, 0

arg_fbtest:     db "--fbtest", 0
arg_tz:         db "--tz", 0
arg_vt:         db "--vt", 0
path_vt_active: db "/sys/class/tty/tty0/active", 0
path_lock:      db "/run/bolt-greet.lock", 0
path_tty0:      db "/dev/tty0", 0

log_start:      db "bolt-greet: starting", 10
log_start_len   equ $ - log_start
log_nodrm:      db "bolt-greet: DRM init failed (need root, gdm stopped)", 10
log_nodrm_len   equ $ - log_nodrm
log_nomaster:   db "bolt-greet: SET_MASTER failed (another display server running?)", 10
log_nomaster_len equ $ - log_nomaster
log_fbtest:     db "bolt-greet: fbtest frame -> /tmp/greet_fb.raw", 10
log_fbtest_len  equ $ - log_fbtest
log_launch:     db "bolt-greet: launching session", 10
log_launch_len  equ $ - log_launch
log_card:       db "bolt-greet: opened ", 0
log_master:     db "bolt-greet: DRM master ok", 10
log_master_len  equ $ - log_master
log_mode_pre:   db "bolt-greet: mode ", 0
log_setcrtc:    db "bolt-greet: SETCRTC ok", 10
log_setcrtc_len equ $ - log_setcrtc
log_wall_ok:    db "bolt-greet: wallpaper ok", 10
log_wall_ok_len equ $ - log_wall_ok
log_wall_no:    db "bolt-greet: no wallpaper (solid bg)", 10
log_wall_no_len equ $ - log_wall_no
log_inputs:     db "bolt-greet: input devices: ", 0
log_menu_up:    db "bolt-greet: menu up", 10
log_menu_up_len equ $ - log_menu_up
log_esc:        db "bolt-greet: exit (Esc)", 10
log_esc_len     equ $ - log_esc
log_sig:        db "bolt-greet: signal, restoring console", 10
log_sig_len     equ $ - log_sig
log_devdrop:    db "bolt-greet: dropped dead input fd", 10
log_devdrop_len equ $ - log_devdrop
log_reassert:   db "bolt-greet: reassert CRTC after suspend", 10
log_reassert_len equ $ - log_reassert
log_vt_away:    db "bolt-greet: VT switched away, released display", 10
log_vt_away_len equ $ - log_vt_away
log_vt_back:    db "bolt-greet: VT back, re-took display", 10
log_vt_back_len equ $ - log_vt_back
log_dup:        db "bolt-greet: another instance is already running", 10
log_dup_len     equ $ - log_dup
log_chvt:       db "bolt-greet: activated own VT", 10
log_chvt_len    equ $ - log_chvt
str_x:          db "x", 0
str_nl:         db 10, 0

section .bss
    align 8
fbtest_mode:    resb 1
tz_offset_min:  resd 1                  ; local-time offset, minutes east of UTC

fb_addr:        resq 1                  ; render target = db_addr[back_idx]
fb_w:           resd 1
fb_h:           resd 1
fb_pitch:       resd 1
fb_size:        resq 1

; Double-buffered presentation: render into the back buffer, PAGE_FLIP it in.
; eDP PSR freezes scanout on idle frames — flips are the reliable wake-up
; (DIRTYFB was not enough on this panel); frame's compositor works the same
; way. First present is a SETCRTC (binds mode + fb in one go).
db_addr:        resq 2
db_handle:      resd 2
db_fbid:        resd 2
back_idx:       resd 1
crtc_bound:     resb 1                  ; 0 until the first SETCRTC
cur_front_fbid: resd 1                  ; what the CRTC scans now (suspend reassert)

; DRM state (struct layouts mirror frame.asm)
drm_fd:         resq 1
drm_card_path:  resb 32
drm_res_buf:    resb 64
drm_fb_ids:     resd DRM_MAX_IDS
drm_crtc_ids:   resd DRM_MAX_IDS
drm_conn_ids:   resd DRM_MAX_IDS
drm_enc_ids:    resd DRM_MAX_IDS
drm_conn_buf:   resb 80
drm_modes_buf:  resb (DRM_MODE_INFO_SIZE * DRM_MAX_MODES)
drm_enc_arr:    resd DRM_MAX_IDS
drm_props_arr:  resd DRM_MAX_PROPS
drm_propvals_arr: resq DRM_MAX_PROPS
drm_encoder_buf: resb 20
drm_crtc_save:  resb 104
drm_crtc_set:   resb 104
drm_dumb_create: resb 32
drm_dumb_map:   resb 16
drm_fb_cmd:     resb 28
drm_dumb_destroy: resb 8
drm_set_conn_id: resd 1
drm_chosen_conn: resd 1
drm_chosen_crtc: resd 1
drm_dumb_pitch: resd 1
drm_dumb_size:  resq 1

WALL_MAX        equ 1920*1200*4
wallpaper_ok:   resb 1
wallpaper_buf:  resb WALL_MAX

input_fds:      resd MAX_INPUTS
input_fd_count: resd 1
pollfds:        resb MAX_INPUTS*8
ev_buf:         resb 24*32
dev_path_buf:   resb 32

cur_year:       resd 1
cur_mon:        resd 1                  ; 1..12
cur_mday:       resd 1
cur_wday:       resd 1                  ; index into wday_names (epoch%7)
cur_hour:       resd 1
cur_min:        resd 1

bat_present:    resb 1
bat_pct:        resd 1
bat_status:     resd 1                  ; 0=dis 1=chg 2=full

filebuf:        resb 64
footer_buf:     resb 128
gs_argv:        resq 3
wait_status:    resd 1
sig_sa_buf:     resb 32
lognum_buf:     resb 16
own_vt:         resd 1                  ; --vt N; 0 = VT gating disabled
vt_fd:          resd 1                  ; /sys/class/tty/tty0/active (or -1)
vt_active:      resb 1                  ; 1 = our VT is foreground
vtbuf:          resb 16
    alignb 8
flip_cmd:       resb 24                 ; struct drm_mode_crtc_page_flip
drm_pollfd:     resb 8                  ; wait_flip's single pollfd

section .text
global _start

; ============================================================================
; entry
; ============================================================================
_start:
    mov dword [tz_offset_min], 120      ; CEST fallback if no --tz given
    ; scan argv[1..] for --fbtest / --tz +HHMM
    mov rbx, [rsp]                      ; argc
    mov r12d, 1
.arg_loop:
    cmp r12, rbx
    jge .arg_done
    mov rdi, [rsp + 8 + r12*8]          ; argv[r12]
    lea rsi, [arg_fbtest]
    call streq_cstr
    jne .arg_tzq
    mov byte [fbtest_mode], 1
    jmp .arg_next
.arg_tzq:
    mov rdi, [rsp + 8 + r12*8]          ; streq_cstr advanced rdi; reload
    lea rsi, [arg_tz]
    call streq_cstr
    jne .arg_vtq
    ; next argv = "+HHMM" / "-HHMM" (date +%z format)
    inc r12
    cmp r12, rbx
    jge .arg_done
    mov rdi, [rsp + 8 + r12*8]
    call parse_tz
    jmp .arg_next
.arg_vtq:
    mov rdi, [rsp + 8 + r12*8]
    lea rsi, [arg_vt]
    call streq_cstr
    jne .arg_next
    inc r12
    cmp r12, rbx
    jge .arg_done
    mov rdi, [rsp + 8 + r12*8]
    call atoi_buf
    mov [own_vt], eax
.arg_next:
    inc r12
    jmp .arg_loop
.arg_done:

    lea rsi, [log_start]
    mov rdx, log_start_len
    call write_stderr

    ; Single instance: flock /run/bolt-greet.lock (auto-released on ANY
    ; process death — no stale pidfiles). Two greeters steal DRM master
    ; from each other and both eat evdev keys. Unwritable /run (fbtest as
    ; a normal user) just skips the guard.
    mov rax, SYS_OPEN
    lea rdi, [path_lock]
    mov esi, 0x42                       ; O_RDWR|O_CREAT
    mov edx, 0o644
    syscall
    test rax, rax
    js  .lock_done
    mov edi, eax                        ; fd held for life (leaked on purpose)
    mov rax, SYS_FLOCK
    mov esi, 6                          ; LOCK_EX|LOCK_NB
    syscall
    test rax, rax
    jns .lock_cloexec
    lea rsi, [log_dup]
    mov rdx, log_dup_len
    call write_stderr
    mov rax, SYS_EXIT
    mov edi, 1
    syscall
.lock_cloexec:
    ; CLOEXEC: sessions must NOT inherit the lock fd — a surviving session
    ; process would keep the flock held long after the greeter exits
    ; ("another instance is already running" with no greeter alive).
    mov rax, SYS_FCNTL
    mov esi, 2                          ; F_SETFD
    mov edx, 1                          ; FD_CLOEXEC
    syscall
.lock_done:

    ; Ctrl+C / kill / hangup restore the console CRTC and exit — a wedged
    ; or invisible greeter must never need a hard reboot.
    mov edi, 2                          ; SIGINT
    call install_exit_handler
    mov edi, 15                         ; SIGTERM
    call install_exit_handler
    mov edi, 1                          ; SIGHUP
    call install_exit_handler

    cmp byte [fbtest_mode], 0
    jne .fbtest_path

    call drm_init
    test rax, rax
    js  .drm_fail
    call load_wallpaper
    cmp byte [wallpaper_ok], 0
    je  .st_wall_no
    lea rsi, [log_wall_ok]
    mov rdx, log_wall_ok_len
    call write_stderr
    jmp .st_wall_done
.st_wall_no:
    lea rsi, [log_wall_no]
    mov rdx, log_wall_no_len
    call write_stderr
.st_wall_done:
    call greeter_loop                   ; returns on Esc
    lea rsi, [log_esc]
    mov rdx, log_esc_len
    call write_stderr
    call drm_teardown
    mov rax, SYS_EXIT
    xor edi, edi
    syscall

.drm_fail:
    lea rsi, [log_nodrm]
    mov rdx, log_nodrm_len
    call write_stderr
    mov rax, SYS_EXIT
    mov edi, 1
    syscall

.fbtest_path:
    call fbtest_init
    call load_wallpaper
    call update_clock
    call update_battery
    call render_frame
    call fbtest_dump
    lea rsi, [log_fbtest]
    mov rdx, log_fbtest_len
    call write_stderr
    mov rax, SYS_EXIT
    xor edi, edi
    syscall

; ============================================================================
; greeter_loop — render, poll evdev with 30s timeout (clock tick), dispatch.
; ============================================================================
greeter_loop:
    push rbx
    call init_input
    call vt_watch_init                  ; /sys active-VT watch (POLLPRI)
    call vt_claim                       ; not on the active VT? chvt to ours
                                        ; (stopping gdm switches the VT away,
                                        ; leaving the fresh greeter invisible)
    xor ebx, ebx                        ; first-frame flag (log "menu up" once)
.gl_iter:
    cmp byte [vt_active], 1
    jne .gl_poll                        ; VT away: no render, no present
    call update_clock
    call update_battery
    call render_frame
    call flush_fb                       ; caches → RAM before the flip
    call present_frame                  ; first: SETCRTC; later: PAGE_FLIP
    test rax, rax
    js  .gl_exit                        ; first bind failed
    test ebx, ebx
    jnz .gl_poll
    inc ebx
    lea rsi, [log_setcrtc]
    mov rdx, log_setcrtc_len
    call write_stderr
    lea rsi, [log_menu_up]
    mov rdx, log_menu_up_len
    call write_stderr
.gl_poll:
    call build_pollfds                  ; eax = nfds (inputs + VT watch)
    mov esi, eax
    mov rax, SYS_POLL
    lea rdi, [pollfds]
    mov edx, 30000                      ; 30s tick for the clock
    syscall
    test rax, rax
    jz  .gl_iter                        ; timeout → refresh clock/battery
    js  .gl_poll                        ; EINTR
    call vt_check                       ; VT switch? release/re-take display
    call drain_input                    ; eax: 0 none, 1-3 launch, 10 susp,
    test eax, eax                       ;      11 off, 20 esc
    jz  .gl_iter
    cmp eax, 20
    je  .gl_exit
    cmp eax, 10
    je  .gl_suspend
    cmp eax, 11
    je  .gl_poweroff
    ; launch session eax(1..3): teardown DRM + input, run, re-init
    mov ebx, eax                        ; close_input clobbers eax/edi
    call close_input
    mov edi, ebx
    call launch_session
    call drm_init
    test rax, rax
    js  .gl_exit
    call load_wallpaper
    call init_input
    xor ebx, ebx
    jmp .gl_iter
.gl_suspend:
    lea rdi, [path_systemctl]
    lea rsi, [argv_suspend]
    call run_child_wait
    lea rsi, [log_reassert]
    mov rdx, log_reassert_len
    call write_stderr
    call drm_reassert                   ; repoint CRTC after resume
    jmp .gl_iter
.gl_poweroff:
    call drm_teardown
    lea rdi, [path_systemctl]
    lea rsi, [argv_poweroff]
    call run_child_wait
    ; if poweroff returns, machine is going down anyway — just exit
    mov rax, SYS_EXIT
    xor edi, edi
    syscall
.gl_exit:
    call close_input
    pop rbx
    ret

; ============================================================================
; launch_session — edi = choice (1..3). Release DRM, run greet-session <n>,
; wait for it. Caller re-inits DRM after.
; ============================================================================
launch_session:
    push rbx
    push r12
    mov r12d, edi                       ; choice 1..3
    lea rsi, [log_launch]
    mov rdx, log_launch_len
    call write_stderr
    lea rax, [arg_gs0]
    mov [gs_argv], rax
    lea rcx, [gs_choice1]
    cmp r12d, 2
    jne .ls_c3q
    lea rcx, [gs_choice2]
.ls_c3q:
    cmp r12d, 3
    jne .ls_set
    lea rcx, [gs_choice3]
.ls_set:
    mov [gs_argv + 8], rcx
    mov qword [gs_argv + 16], 0
    call drm_teardown
    lea rdi, [path_greetsess]
    lea rsi, [gs_argv]
    call run_child_wait
    pop r12
    pop rbx
    ret

; ============================================================================
; run_child_wait — rdi = path, rsi = argv. fork; child execve; parent wait4.
; ============================================================================
run_child_wait:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rax, SYS_FORK
    syscall
    test rax, rax
    jz  .rc_child
    js  .rc_done
    mov rbx, rax
.rc_wait:
    mov rax, SYS_WAIT4
    mov rdi, rbx
    lea rsi, [wait_status]
    xor edx, edx
    xor r10d, r10d
    syscall
    cmp rax, -4                         ; EINTR
    je  .rc_wait
    jmp .rc_done
.rc_child:
    mov rax, SYS_EXECVE
    mov rdi, r12
    mov rsi, r13
    lea rdx, [child_envp]
    syscall
    mov rax, SYS_EXIT
    mov edi, 127
    syscall
.rc_done:
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; init_input / close_input / build_pollfds — evdev keyboards (frame pattern)
; ============================================================================
init_input:
    push rbx
    push r12
    lea rdi, [input_fds]
    mov eax, -1
    mov ecx, MAX_INPUTS
    rep stosd
    mov dword [input_fd_count], 0
    xor ebx, ebx
.ii_loop:
    cmp ebx, INPUT_DEV_MAX
    jge .ii_done
    cmp dword [input_fd_count], MAX_INPUTS
    jge .ii_done
    ; "/dev/input/eventN"
    lea rdi, [dev_path_buf]
    lea rsi, [input_dev_pre]
.ii_cp:
    mov al, [rsi]
    test al, al
    jz  .ii_cp_done
    mov [rdi], al
    inc rsi
    inc rdi
    jmp .ii_cp
.ii_cp_done:
    mov eax, ebx
    call u32_to_ascii
    mov byte [rdi], 0
    mov rax, SYS_OPEN
    lea rdi, [dev_path_buf]
    mov esi, O_NONBLOCK                 ; O_RDONLY|O_NONBLOCK
    xor edx, edx
    syscall
    test rax, rax
    js  .ii_next
    mov r12d, [input_fd_count]
    mov [input_fds + r12*4], eax
    inc dword [input_fd_count]
.ii_next:
    inc ebx
    jmp .ii_loop
.ii_done:
    lea rsi, [log_inputs]
    call write_cstr_stderr
    mov eax, [input_fd_count]
    call write_u32_stderr
    lea rsi, [str_nl]
    call write_cstr_stderr
    pop r12
    pop rbx
    ret

close_input:
    push rbx
    xor ebx, ebx
.ci_loop:
    cmp ebx, [input_fd_count]
    jge .ci_done
    mov edi, [input_fds + rbx*4]
    mov rax, SYS_CLOSE
    syscall
    inc ebx
    jmp .ci_loop
.ci_done:
    mov dword [input_fd_count], 0
    pop rbx
    ret

build_pollfds:
    push rbx
    xor ebx, ebx
.bp_loop:
    cmp ebx, [input_fd_count]
    jge .bp_vt
    mov eax, [input_fds + rbx*4]
    mov [pollfds + rbx*8], eax          ; fd
    mov word [pollfds + rbx*8 + 4], 1   ; events = POLLIN
    mov word [pollfds + rbx*8 + 6], 0   ; revents
    inc ebx
    jmp .bp_loop
.bp_vt:
    ; active-VT watch as the extra last slot (sysfs_notify → POLLPRI)
    cmp dword [vt_fd], 0
    jl  .bp_done
    mov eax, [vt_fd]
    mov [pollfds + rbx*8], eax
    mov word [pollfds + rbx*8 + 4], 2   ; POLLPRI
    mov word [pollfds + rbx*8 + 6], 0
    inc ebx
.bp_done:
    mov eax, ebx                        ; nfds for the caller
    pop rbx
    ret

; ============================================================================
; drain_input — read all readable fds; returns eax action
; (0 none/redraw, 1..3 launch, 10 suspend, 11 poweroff).
; ============================================================================
drain_input:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor r14d, r14d
    xor ebx, ebx
.di_dev:
    cmp ebx, [input_fd_count]
    jge .di_done
    movzx eax, word [pollfds + rbx*8 + 6]
    test al, 0x38                       ; POLLERR|POLLHUP|POLLNVAL: dead fd —
    jnz .di_drop                        ; close + remove or poll spins forever
    test al, 1                          ; POLLIN
    jz  .di_next
    mov r12d, [input_fds + rbx*4]
.di_read:
    mov rax, SYS_READ
    mov edi, r12d
    lea rsi, [ev_buf]
    mov edx, 24*32
    syscall
    test rax, rax
    jle .di_next
    mov r15, rax                        ; bytes read
    xor r13d, r13d
.di_ev:
    cmp r13, r15
    jge .di_read
    movzx ecx, word [ev_buf + r13 + 16] ; type
    cmp ecx, EV_KEY
    jne .di_ev_next
    mov ecx, [ev_buf + r13 + 20]        ; value (1=press, 2=repeat)
    cmp ecx, 1
    jne .di_ev_next
    movzx edx, word [ev_buf + r13 + 18] ; keycode
    cmp byte [vt_active], 1             ; keys only count on OUR VT — evdev
    jne .di_ev_next                     ; is global, the console focus is not
    call handle_key
    test eax, eax
    jz  .di_ev_next
    mov r14d, eax
    jmp .di_done                        ; action → stop processing
.di_ev_next:
    add r13, 24
    jmp .di_ev
.di_drop:
    ; close the dead fd, swap the last entry into this slot, retry the slot
    mov edi, [input_fds + rbx*4]
    mov rax, SYS_CLOSE
    syscall
    mov eax, [input_fd_count]
    dec eax
    mov [input_fd_count], eax
    mov ecx, [input_fds + rax*4]
    mov [input_fds + rbx*4], ecx
    movzx ecx, word [pollfds + rax*8 + 6]
    mov [pollfds + rbx*8 + 6], cx
    lea rsi, [log_devdrop]
    mov rdx, log_devdrop_len
    call write_stderr
    jmp .di_dev                         ; same index now holds the swapped fd
.di_next:
    inc ebx
    jmp .di_dev
.di_done:
    mov eax, r14d
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; handle_key — edx = keycode. 1/2/3 launch directly; s suspend, p poweroff,
; Esc exit. Returns 0 (ignore), 1..3, 10, 11, 20.
; ============================================================================
handle_key:
    cmp edx, KEY_ESC
    je  .hk_esc
    cmp edx, KEY_1
    je  .hk_s1
    cmp edx, KEY_2
    je  .hk_s2
    cmp edx, KEY_3
    je  .hk_s3
    cmp edx, KEY_S
    je  .hk_suspend
    cmp edx, KEY_P
    je  .hk_power
    xor eax, eax
    ret
.hk_s1:
    mov eax, 1
    ret
.hk_s2:
    mov eax, 2
    ret
.hk_s3:
    mov eax, 3
    ret
.hk_suspend:
    mov eax, 10
    ret
.hk_power:
    mov eax, 11
    ret
.hk_esc:
    mov eax, 20
    ret

; ============================================================================
; render_frame — wallpaper + strip-like top info bar + bottom session
; selector. The wallpaper stays unobstructed in between.
; ============================================================================
render_frame:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call draw_background

    ; ---- top bar: full width, TOPBAR_H, dark ----
    xor edi, edi
    xor esi, esi
    mov edx, [fb_w]
    mov ecx, TOPBAR_H
    mov r8d, COL_BG
    call fill_rect
    ; "CHasm" accent, left
    mov edi, 16
    mov esi, 4
    lea rdx, [str_title]
    mov ecx, 2
    mov r8d, COL_ACCENT
    call draw_cstr
    ; key hints, dim, after the title
    mov edi, 200
    mov esi, 4
    lea rdx, [str_hints]
    mov ecx, 2
    mov r8d, COL_DIM
    call draw_cstr
    ; date/clock/battery, right-aligned
    call build_footer
    lea rdi, [footer_buf]
    call cstr_len
    shl eax, 4                          ; * 8px * scale 2
    mov edi, [fb_w]
    sub edi, 16
    sub edi, eax
    mov esi, 4
    lea rdx, [footer_buf]
    mov ecx, 2
    mov r8d, COL_TEXT
    call draw_cstr

    ; ---- bottom bar: full width, BOTBAR_H, dark ----
    xor edi, edi
    mov esi, [fb_h]
    sub esi, BOTBAR_H
    mov edx, [fb_w]
    mov ecx, BOTBAR_H
    mov r8d, COL_BG
    call fill_rect
    ; three sessions centered at W/6, W/2, 5W/6
    xor r14d, r14d
.rf_row:
    cmp r14d, 3
    jge .rf_rows_done
    mov eax, r14d
    shl eax, 1
    inc eax                             ; 2i+1
    imul eax, [fb_w]
    xor edx, edx
    mov ecx, 6
    div ecx
    mov r15d, eax                       ; centre x
    lea r13, [str_row0]
    cmp r14d, 1
    jne .rf_l2q
    lea r13, [str_row1]
.rf_l2q:
    cmp r14d, 2
    jne .rf_lbl_ok
    lea r13, [str_row2]
.rf_lbl_ok:
    mov edi, r15d
    mov esi, [fb_h]
    sub esi, BOTBAR_H - 16
    mov rdx, r13
    mov ecx, 2
    mov r8d, COL_TEXT
    call draw_cstr_centered
    inc r14d
    jmp .rf_row
.rf_rows_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; cstr_len — rdi = NUL-terminated string → eax = length. Preserves rdi.
cstr_len:
    xor eax, eax
.cl_loop:
    cmp byte [rdi + rax], 0
    je  .cl_done
    inc eax
    jmp .cl_loop
.cl_done:
    ret

; ============================================================================
; draw_background — wallpaper blit or solid fill.
; ============================================================================
draw_background:
    push rbx
    push r12
    push r13
    push r14
    cmp byte [wallpaper_ok], 0
    je  .db_solid
    xor r12d, r12d                      ; y
    mov r13d, [fb_h]
    mov r14d, [fb_w]
    shl r14d, 2                         ; src stride bytes
.db_row:
    cmp r12d, r13d
    jge .db_done
    mov eax, r12d
    imul eax, r14d
    lea rsi, [wallpaper_buf]
    add rsi, rax
    mov eax, r12d
    imul eax, [fb_pitch]
    mov rdi, [fb_addr]
    add rdi, rax
    mov ecx, r14d
    shr ecx, 3
    rep movsq
    inc r12d
    jmp .db_row
.db_solid:
    xor edi, edi
    xor esi, esi
    mov edx, [fb_w]
    mov ecx, [fb_h]
    mov r8d, COL_BG
    call fill_rect
.db_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; fill_rect — edi=x esi=y edx=w ecx=h r8d=colour. Clips. Preserves r12-r15.
; ============================================================================
fill_rect:
    push rbx
    push r12
    push r13
    ; clip left/top
    test edi, edi
    jns .fr_x0
    add edx, edi
    xor edi, edi
.fr_x0:
    test esi, esi
    jns .fr_y0
    add ecx, esi
    xor esi, esi
.fr_y0:
    mov eax, edi
    add eax, edx
    cmp eax, [fb_w]
    jle .fr_xr
    mov edx, [fb_w]
    sub edx, edi
.fr_xr:
    mov eax, esi
    add eax, ecx
    cmp eax, [fb_h]
    jle .fr_yr
    mov ecx, [fb_h]
    sub ecx, esi
.fr_yr:
    test edx, edx
    jle .fr_done
    test ecx, ecx
    jle .fr_done
    mov r12d, ecx                       ; rows remaining
    ; base = fb_addr + y*pitch + x*4
    mov eax, esi
    imul eax, [fb_pitch]
    mov rbx, [fb_addr]
    add rbx, rax
    mov eax, edi
    shl eax, 2
    add rbx, rax
    mov r13d, edx                       ; width dwords
.fr_rows:
    mov rdi, rbx
    mov ecx, r13d
    mov eax, r8d
    rep stosd
    mov eax, [fb_pitch]
    add rbx, rax
    dec r12d
    jnz .fr_rows
.fr_done:
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; draw_cstr — edi=x esi=y rdx=cstr ecx=scale r8d=colour. Draws left-aligned.
; draw_cstr_centered — same but edi = center x.
; ============================================================================
draw_cstr_centered:
    push rbx
    push rdx
    ; width = strlen * 8 * scale
    mov rbx, rdx
    xor eax, eax
.dc_len:
    cmp byte [rbx + rax], 0
    je  .dc_len_done
    inc eax
    jmp .dc_len
.dc_len_done:
    imul eax, ecx
    shl eax, 3                          ; *8
    shr eax, 1                          ; /2
    sub edi, eax
    pop rdx
    pop rbx
    ; fallthrough
draw_cstr:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdx                        ; str
    mov r13d, edi                       ; x cursor
    mov r14d, esi                       ; y
    mov r15d, ecx                       ; scale
.ds_loop:
    movzx eax, byte [r12]
    test eax, eax
    jz  .ds_done
    mov edi, r13d
    mov esi, r14d
    mov ecx, r15d
    ; r8d already colour
    call draw_glyph                     ; eax = char
    mov eax, r15d
    shl eax, 3
    add r13d, eax                       ; advance 8*scale
    inc r12
    jmp .ds_loop
.ds_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; draw_glyph — eax=ascii edi=x esi=y ecx=scale r8d=colour. 8x16 font, each
; font pixel becomes scale x scale. Transparent background (skip 0 bits).
; Preserves r12-r15.
; ============================================================================
draw_glyph:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub eax, 32
    cmp eax, 94
    ja  .dg_done                        ; outside 32..126 → skip
    shl eax, 4                          ; *16 bytes/glyph
    lea rbx, [greet_font]
    add rbx, rax                        ; glyph rows
    mov r12d, edi                       ; x0
    mov r13d, esi                       ; y0
    mov r14d, ecx                       ; scale
    xor r15d, r15d                      ; row 0..15
.dg_row:
    cmp r15d, 16
    jge .dg_done
    movzx ebp, byte [rbx + r15]         ; row bits
    test ebp, ebp
    jz  .dg_next_row                    ; blank row fast path
    xor r9d, r9d                        ; col 0..7
.dg_col:
    cmp r9d, 8
    jge .dg_next_row
    mov eax, 0x80
    mov ecx, r9d
    shr eax, cl
    test ebp, eax
    jz  .dg_next_col
    ; fill scale x scale block at (x0 + col*scale, y0 + row*scale)
    mov edi, r9d
    imul edi, r14d
    add edi, r12d
    mov esi, r15d
    imul esi, r14d
    add esi, r13d
    mov edx, r14d
    mov ecx, r14d
    call fill_rect
.dg_next_col:
    inc r9d
    jmp .dg_col
.dg_next_row:
    inc r15d
    jmp .dg_row
.dg_done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; build_footer — "Sat 4 Jul 2026   14:32   BAT 87% chg" into footer_buf.
; ============================================================================
build_footer:
    push rbx
    lea rbx, [footer_buf]
    mov eax, [cur_wday]
    lea rsi, [wday_names]
    imul eax, 4
    add rsi, rax
    call fcat_cstr
    mov byte [rbx], ' '
    inc rbx
    mov eax, [cur_mday]
    call fcat_u32
    mov byte [rbx], ' '
    inc rbx
    mov eax, [cur_mon]
    dec eax
    lea rsi, [mon_names]
    imul eax, 4
    add rsi, rax
    call fcat_cstr
    mov byte [rbx], ' '
    inc rbx
    mov eax, [cur_year]
    call fcat_u32
    lea rsi, [str_sep]
    call fcat_cstr
    mov eax, [cur_hour]
    call fcat_2d
    mov byte [rbx], ':'
    inc rbx
    mov eax, [cur_min]
    call fcat_2d
    lea rsi, [str_sep]
    call fcat_cstr
    cmp byte [bat_present], 0
    je  .bf_ac
    lea rsi, [str_bat]
    call fcat_cstr
    mov eax, [bat_pct]
    call fcat_u32
    lea rsi, [str_pctsp]
    call fcat_cstr
    mov eax, [bat_status]
    lea rsi, [str_dis]
    cmp eax, 1
    jne .bf_full_q
    lea rsi, [str_chg]
.bf_full_q:
    cmp eax, 2
    jne .bf_emit
    lea rsi, [str_full]
.bf_emit:
    call fcat_cstr
    jmp .bf_end
.bf_ac:
    lea rsi, [str_nobat]
    call fcat_cstr
.bf_end:
    mov byte [rbx], 0
    pop rbx
    ret

; fcat_cstr — append cstr [rsi] at cursor rbx.
fcat_cstr:
    mov al, [rsi]
    test al, al
    jz  .fc_d
    mov [rbx], al
    inc rbx
    inc rsi
    jmp fcat_cstr
.fc_d:
    ret

; fcat_u32 — append decimal eax at cursor rbx.
fcat_u32:
    push rsi
    mov rdi, rbx
    call u32_to_ascii
    mov rbx, rdi
    pop rsi
    ret

; fcat_2d — append zero-padded 2-digit eax.
fcat_2d:
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    mov [rbx], al
    inc rbx
    add dl, '0'
    mov [rbx], dl
    inc rbx
    ret

; ============================================================================
; update_clock — time() → civil date/time using tz_offset_min.
; Days-from-epoch → y/m/d via Howard Hinnant's civil_from_days algorithm.
; ============================================================================
update_clock:
    push rbx
    push r12
    mov rax, SYS_TIME
    xor edi, edi
    syscall                             ; rax = unix seconds
    ; apply tz offset
    movsxd rcx, dword [tz_offset_min]
    imul rcx, 60
    add rax, rcx
    ; split days / seconds-of-day
    mov rcx, 86400
    xor edx, edx
    div rcx                             ; rax = days, rdx = secs of day
    mov rbx, rax                        ; days since epoch
    mov rax, rdx
    xor edx, edx
    mov ecx, 3600
    div ecx
    mov [cur_hour], eax
    mov eax, edx
    xor edx, edx
    mov ecx, 60
    div ecx
    mov [cur_min], eax
    ; weekday: days % 7 → wday_names index (1970-01-01 = Thu at index 0)
    mov rax, rbx
    xor edx, edx
    mov ecx, 7
    div ecx
    mov [cur_wday], edx
    ; civil_from_days(z = days):
    ;   z += 719468
    ;   era = z / 146097
    ;   doe = z % 146097
    ;   yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365
    ;   y   = yoe + era*400
    ;   doy = doe - (365*yoe + yoe/4 - yoe/100)
    ;   mp  = (5*doy + 2)/153
    ;   d   = doy - (153*mp+2)/5 + 1
    ;   m   = mp + (mp < 10 ? 3 : -9)
    ;   y  += (m <= 2)
    mov rax, rbx
    add rax, 719468
    mov rcx, 146097
    xor edx, edx
    div rcx                             ; rax=era rdx=doe
    mov r12, rax                        ; era
    mov rbx, rdx                        ; doe
    ; yoe
    mov rax, rbx
    mov rcx, 1460
    xor edx, edx
    div rcx
    mov r8, rax                         ; doe/1460
    mov rax, rbx
    mov rcx, 36524
    xor edx, edx
    div rcx
    mov r9, rax                         ; doe/36524
    mov rax, rbx
    mov rcx, 146096
    xor edx, edx
    div rcx
    mov r10, rax                        ; doe/146096
    mov rax, rbx
    sub rax, r8
    add rax, r9
    sub rax, r10
    mov rcx, 365
    xor edx, edx
    div rcx                             ; rax = yoe
    mov r11, rax                        ; yoe
    ; y = yoe + era*400
    imul r12, 400
    add r12, rax                        ; r12 = y (pre-adjust)
    ; doy = doe - (365*yoe + yoe/4 - yoe/100)
    mov rax, r11
    imul rax, 365
    mov rcx, r11
    shr rcx, 2
    add rax, rcx
    mov rcx, r11
    xor edx, edx
    push rax
    mov rax, rcx
    mov rcx, 100
    div rcx
    mov rcx, rax                        ; yoe/100
    pop rax
    sub rax, rcx
    mov rcx, rbx
    sub rcx, rax                        ; rcx = doy
    ; mp = (5*doy+2)/153
    mov rax, rcx
    imul rax, 5
    add rax, 2
    xor edx, edx
    mov r8, 153
    div r8                              ; rax = mp
    mov r9, rax                         ; mp
    ; d = doy - (153*mp+2)/5 + 1
    imul rax, 153
    add rax, 2
    xor edx, edx
    mov r8, 5
    div r8
    sub rcx, rax
    inc rcx
    mov [cur_mday], ecx
    ; m = mp + (mp<10 ? 3 : -9)
    mov rax, r9
    cmp rax, 10
    jl  .uc_mlt
    sub rax, 9
    jmp .uc_mset
.uc_mlt:
    add rax, 3
.uc_mset:
    mov [cur_mon], eax
    ; y += (m<=2)
    cmp eax, 2
    jg  .uc_yset
    inc r12
.uc_yset:
    mov [cur_year], r12d
    pop r12
    pop rbx
    ret

; ============================================================================
; update_battery — read /sys BAT0 (fall back BAT1) capacity + status.
; ============================================================================
update_battery:
    push rbx
    mov byte [bat_present], 0
    lea rdi, [path_bat0_cap]
    call read_small_file                ; rax=len or -1, filebuf filled
    test rax, rax
    jns .ub_have
    lea rdi, [path_bat1_cap]
    call read_small_file
    test rax, rax
    js  .ub_done
    ; using BAT1 → status path 1
    lea rbx, [path_bat1_stat]
    jmp .ub_parse
.ub_have:
    lea rbx, [path_bat0_stat]
.ub_parse:
    mov byte [bat_present], 1
    ; parse int from filebuf
    lea rdi, [filebuf]
    call atoi_buf
    mov [bat_pct], eax
    ; status
    mov rdi, rbx
    call read_small_file
    test rax, rax
    js  .ub_dis
    mov al, [filebuf]
    cmp al, 'C'                         ; Charging
    je  .ub_chg
    cmp al, 'F'                         ; Full
    je  .ub_full
.ub_dis:
    mov dword [bat_status], 0
    jmp .ub_done
.ub_chg:
    mov dword [bat_status], 1
    jmp .ub_done
.ub_full:
    mov dword [bat_status], 2
.ub_done:
    pop rbx
    ret

; read_small_file — rdi=path. Reads up to 63 bytes into filebuf (NUL-term).
; Returns rax = bytes read or -1.
read_small_file:
    push rbx
    mov rax, SYS_OPEN
    xor esi, esi                        ; O_RDONLY
    xor edx, edx
    syscall
    test rax, rax
    js  .rs_err
    mov rbx, rax
    mov rax, SYS_READ
    mov rdi, rbx
    lea rsi, [filebuf]
    mov edx, 63
    syscall
    push rax
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    pop rax
    test rax, rax
    js  .rs_err
    mov byte [filebuf + rax], 0
    pop rbx
    ret
.rs_err:
    mov rax, -1
    pop rbx
    ret

; parse_tz — rdi = "+HHMM" / "-HHMM" (date +%z). Sets tz_offset_min.
parse_tz:
    movzx ecx, byte [rdi]               ; sign
    cmp cl, '+'
    je  .pt_body
    cmp cl, '-'
    jne .pt_out                         ; malformed → keep default
.pt_body:
    movzx eax, byte [rdi + 1]
    sub eax, '0'
    imul eax, 10
    movzx edx, byte [rdi + 2]
    sub edx, '0'
    add eax, edx
    imul eax, 60                        ; hours → minutes
    movzx edx, byte [rdi + 3]
    sub edx, '0'
    imul edx, 10
    add eax, edx
    movzx edx, byte [rdi + 4]
    sub edx, '0'
    add eax, edx
    cmp cl, '-'
    jne .pt_set
    neg eax
.pt_set:
    mov [tz_offset_min], eax
.pt_out:
    ret

; atoi_buf — rdi=buf. Parses leading decimal. Returns eax.
atoi_buf:
    xor eax, eax
.ab_loop:
    movzx edx, byte [rdi]
    sub edx, '0'
    cmp edx, 9
    ja  .ab_done
    imul eax, eax, 10
    add eax, edx
    inc rdi
    jmp .ab_loop
.ab_done:
    ret

; ============================================================================
; load_wallpaper — read ~/.framebg; sets wallpaper_ok if size==w*h*4.
; ============================================================================
load_wallpaper:
    push rbx
    push r12
    mov byte [wallpaper_ok], 0
    mov rax, SYS_OPEN
    lea rdi, [path_framebg]
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js  .lw_done
    mov rbx, rax
    ; expected size
    mov r12d, [fb_w]
    imul r12d, [fb_h]
    shl r12, 2
    cmp r12, WALL_MAX
    ja  .lw_close                       ; buffer too small for this mode
    ; read loop
    lea rsi, [wallpaper_buf]
    xor r8, r8                          ; total
.lw_read:
    mov rax, SYS_READ
    mov rdi, rbx
    mov rdx, r12
    sub rdx, r8
    jz  .lw_fullq
    syscall
    test rax, rax
    jle .lw_fullq
    add r8, rax
    add rsi, rax
    jmp .lw_read
.lw_fullq:
    cmp r8, r12
    jne .lw_close
    mov byte [wallpaper_ok], 1
.lw_close:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.lw_done:
    pop r12
    pop rbx
    ret

; ============================================================================
; DRM — init / reassert / teardown (frame.asm's proven sequences)
; ============================================================================
; drm_init — full bring-up: open, SET_MASTER, resources, connector, encoder,
; CRTC save, CREATE_DUMB, MAP_DUMB, mmap, ADDFB, SETCRTC.
; Returns rax >= 0 ok, < 0 fail.
drm_init:
    push rbx
    push r12
    push r13
    call drm_try_open
    test rax, rax
    js  .di_fail
    mov [drm_fd], rax
    lea rsi, [log_card]
    call write_cstr_stderr
    lea rsi, [drm_card_path]
    call write_cstr_stderr
    lea rsi, [str_nl]
    call write_cstr_stderr
    ; SET_MASTER
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_SET_MASTER
    xor edx, edx
    syscall
    test rax, rax
    js  .di_master_fail
    lea rsi, [log_master]
    mov rdx, log_master_len
    call write_stderr
    ; resources
    call drm_get_resources
    test rax, rax
    js  .di_close_fail
    ; first connected connector
    call drm_find_connector
    test eax, eax
    jz  .di_close_fail
    mov [drm_chosen_conn], r12d
    ; encoder → CRTC
    lea rdi, [drm_encoder_buf]
    xor eax, eax
    mov ecx, 5
    rep stosd
    mov eax, [drm_conn_buf + 44]        ; encoder_id
    mov [drm_encoder_buf], eax
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_GETENCODER
    lea rdx, [drm_encoder_buf]
    syscall
    test rax, rax
    js  .di_close_fail
    mov eax, [drm_encoder_buf + 8]      ; current crtc_id
    test eax, eax
    jnz .di_have_crtc
    mov ecx, [drm_encoder_buf + 12]     ; possible_crtcs bitmask
    bsf rdx, rcx
    mov eax, [drm_crtc_ids + rdx*4]
.di_have_crtc:
    mov r13d, eax
    mov [drm_chosen_crtc], eax
    ; save current CRTC for restore
    lea rdi, [drm_crtc_save]
    xor eax, eax
    mov ecx, 13
    rep stosq
    mov [drm_crtc_save + 12], r13d
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_GETCRTC
    lea rdx, [drm_crtc_save]
    syscall
    ; mode dims
    movzx eax, word [drm_modes_buf + 4] ; hdisplay
    mov [fb_w], eax
    movzx eax, word [drm_modes_buf + 14] ; vdisplay
    mov [fb_h], eax
    lea rsi, [log_mode_pre]
    call write_cstr_stderr
    mov eax, [fb_w]
    call write_u32_stderr
    lea rsi, [str_x]
    call write_cstr_stderr
    mov eax, [fb_h]
    call write_u32_stderr
    lea rsi, [str_nl]
    call write_cstr_stderr
    ; Two dumb buffers + fbs (double-buffered flips). No SETCRTC here —
    ; greeter_loop renders the first frame FIRST, then present_frame binds
    ; the CRTC to it, so the panel never shows a black buffer.
    xor ebx, ebx
.di_buf_loop:
    cmp ebx, 2
    jge .di_bufs_done
    call drm_create_buffer              ; ebx = index
    test rax, rax
    js  .di_close_fail
    inc ebx
    jmp .di_buf_loop
.di_bufs_done:
    mov dword [back_idx], 0
    mov byte [crtc_bound], 0
    mov rax, [db_addr]
    mov [fb_addr], rax
    xor eax, eax
    jmp .di_out
.di_master_fail:
    lea rsi, [log_nomaster]
    mov rdx, log_nomaster_len
    call write_stderr
.di_close_fail:
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_DROP_MASTER
    xor edx, edx
    syscall
    mov rax, SYS_CLOSE
    mov rdi, [drm_fd]
    syscall
.di_fail:
    mov rax, -1
.di_out:
    pop r13
    pop r12
    pop rbx
    ret

; flush_fb — clflush the back buffer so the render reaches RAM before the
; flip (scanout is not CPU-cache coherent). ~9 MB per redraw; redraws
; happen per keypress / 30 s tick.
flush_fb:
    mov rdi, [fb_addr]
    mov rcx, [fb_size]
.ff_loop:
    clflush [rdi]
    add rdi, 64
    sub rcx, 64
    ja  .ff_loop
    sfence
    ret

; vt_watch_init — open /sys/class/tty/tty0/active (pollable: POLLPRI on VT
; switch) and prime vt_active. own_vt 0 (no --vt) disables gating entirely.
vt_watch_init:
    mov dword [vt_fd], -1
    mov byte [vt_active], 1
    cmp dword [own_vt], 0
    je  .vw_out                         ; gating disabled
    mov rax, SYS_OPEN
    lea rdi, [path_vt_active]
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js  .vw_out                         ; no sysfs? gating disabled
    mov [vt_fd], eax
    mov edi, eax                        ; CLOEXEC — don't leak into sessions
    mov rax, SYS_FCNTL
    mov esi, 2
    mov edx, 1
    syscall
    call vt_read_active
    cmp eax, [own_vt]
    sete al
    mov [vt_active], al
.vw_out:
    ret

; vt_claim — if we own a VT and it is not the active one, VT_ACTIVATE it
; (what every display manager does at startup). No-op when already active
; or gating is disabled.
vt_claim:
    cmp dword [own_vt], 0
    je  .vcl_out
    cmp byte [vt_active], 1
    je  .vcl_out
    mov rax, SYS_OPEN
    lea rdi, [path_tty0]
    mov esi, O_RDWR
    xor edx, edx
    syscall
    test rax, rax
    js  .vcl_out
    push rax
    mov rdi, rax
    mov rax, SYS_IOCTL
    mov esi, VT_ACTIVATE
    mov edx, [own_vt]
    syscall
    mov rdi, [rsp]
    mov rax, SYS_IOCTL
    mov esi, VT_WAITACTIVE
    mov edx, [own_vt]
    syscall
    pop rdi
    mov rax, SYS_CLOSE
    syscall
    mov byte [vt_active], 1
    lea rsi, [log_chvt]
    mov rdx, log_chvt_len
    call write_stderr
.vcl_out:
    ret

; vt_read_active — pread the watch file, parse "ttyN" → eax = N (0 on error).
vt_read_active:
    mov rax, SYS_LSEEK
    mov edi, [vt_fd]
    xor esi, esi
    xor edx, edx
    syscall
    mov rax, SYS_READ
    mov edi, [vt_fd]
    lea rsi, [vtbuf]
    mov edx, 15
    syscall
    test rax, rax
    jle .vr_err
    mov byte [vtbuf + rax], 0
    lea rdi, [vtbuf + 3]                ; skip "tty"
    call atoi_buf
    ret
.vr_err:
    xor eax, eax
    ret

; vt_check — called on every poll wake. On VT-away: give the console back
; (restore saved CRTC, drop master) so the user is not typing blind into an
; invisible shell. On VT-return: re-take master; the next .gl_iter render
; re-binds via SETCRTC (crtc_bound=0).
vt_check:
    cmp dword [vt_fd], 0
    jl  .vc_out
    call vt_read_active
    cmp eax, [own_vt]
    sete al
    cmp al, [vt_active]
    je  .vc_out
    mov [vt_active], al
    test al, al
    jz  .vc_away
    ; back: re-take the device
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_SET_MASTER
    xor edx, edx
    syscall
    mov byte [crtc_bound], 0            ; next present = SETCRTC
    lea rsi, [log_vt_back]
    mov rdx, log_vt_back_len
    call write_stderr
    ret
.vc_away:
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_SETCRTC
    lea rdx, [drm_crtc_save]
    syscall
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_DROP_MASTER
    xor edx, edx
    syscall
    lea rsi, [log_vt_away]
    mov rdx, log_vt_away_len
    call write_stderr
.vc_out:
    ret

; install_exit_handler — edi = signal number. Kernel sigaction ABI needs
; SA_RESTORER + trampoline (libc-free). Lifted from frame.
install_exit_handler:
    push rdi
    lea rdi, [sig_sa_buf]
    lea rax, [exit_handler]
    mov [rdi + 0], rax                  ; sa_handler
    mov qword [rdi + 8], SA_RESTORER    ; sa_flags
    lea rax, [sig_restorer]
    mov [rdi + 16], rax                 ; sa_restorer
    mov qword [rdi + 24], 0             ; sa_mask
    pop rdi
    mov rax, SYS_RT_SIGACTION
    lea rsi, [sig_sa_buf]
    xor edx, edx
    mov r10, 8
    syscall
    ret

sig_restorer:
    mov rax, SYS_RT_SIGRETURN
    syscall

; exit_handler — Ctrl+C / kill / hangup: restore the console CRTC, drop
; master, exit. Raw syscalls only — async-signal-safe.
exit_handler:
    lea rsi, [log_sig]
    mov rdx, log_sig_len
    call write_stderr
    cmp byte [fbtest_mode], 0
    jne .eh_out
    call drm_teardown
.eh_out:
    mov rax, SYS_EXIT
    xor edi, edi
    syscall

; drm_create_buffer — ebx = buffer index (0/1). CREATE_DUMB + MAP_DUMB +
; mmap + ADDFB into db_handle/db_addr/db_fbid[ebx]. rax = 0 ok / -1 fail.
drm_create_buffer:
    lea rdi, [drm_dumb_create]
    xor eax, eax
    mov ecx, 4
    rep stosq
    mov eax, [fb_w]
    mov [drm_dumb_create + 4], eax      ; width
    mov eax, [fb_h]
    mov [drm_dumb_create + 0], eax      ; height
    mov dword [drm_dumb_create + 8], 32
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_CREATE_DUMB
    lea rdx, [drm_dumb_create]
    syscall
    test rax, rax
    js  .cb_fail
    mov eax, [drm_dumb_create + 16]
    mov [db_handle + rbx*4], eax
    mov eax, [drm_dumb_create + 20]
    mov [fb_pitch], eax
    mov rax, [drm_dumb_create + 24]
    mov [fb_size], rax
    mov [drm_dumb_size], rax
    ; MAP_DUMB
    lea rdi, [drm_dumb_map]
    xor eax, eax
    mov ecx, 2
    rep stosq
    mov eax, [db_handle + rbx*4]
    mov [drm_dumb_map], eax
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_MAP_DUMB
    lea rdx, [drm_dumb_map]
    syscall
    test rax, rax
    js  .cb_fail
    ; mmap
    mov rax, SYS_MMAP
    xor edi, edi
    mov rsi, [drm_dumb_size]
    mov edx, PROT_RW
    mov r10d, MAP_SHARED
    mov r8, [drm_fd]
    mov r9, [drm_dumb_map + 8]
    syscall
    cmp rax, -4096
    ja  .cb_fail
    mov [db_addr + rbx*8], rax
    ; ADDFB
    lea rdi, [drm_fb_cmd]
    xor eax, eax
    mov ecx, 7
    rep stosd
    mov eax, [fb_w]
    mov [drm_fb_cmd + 4], eax
    mov eax, [fb_h]
    mov [drm_fb_cmd + 8], eax
    mov eax, [fb_pitch]
    mov [drm_fb_cmd + 12], eax
    mov dword [drm_fb_cmd + 16], 32
    mov dword [drm_fb_cmd + 20], 24
    mov eax, [db_handle + rbx*4]
    mov [drm_fb_cmd + 24], eax
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_ADDFB
    lea rdx, [drm_fb_cmd]
    syscall
    test rax, rax
    js  .cb_fail
    mov eax, [drm_fb_cmd]
    mov [db_fbid + rbx*4], eax
    xor eax, eax
    ret
.cb_fail:
    mov rax, -1
    ret

; present_frame — put the just-rendered back buffer on screen. First call
; binds via SETCRTC (mode + fb); later calls PAGE_FLIP + wait for the flip
; event (flips are what wake eDP PSR reliably). Swaps back_idx on success.
; rax = 0 ok / -1 the first SETCRTC failed.
present_frame:
    push rbx
    push r12
    mov r12d, [back_idx]
    mov eax, [db_fbid + r12*4]
    mov [cur_front_fbid], eax
    cmp byte [crtc_bound], 0
    jne .pf_flip
    call drm_reassert                   ; SETCRTC cur_front_fbid
    test rax, rax
    js  .pf_out                         ; leave crtc_bound 0; caller bails
    mov byte [crtc_bound], 1
    jmp .pf_swap
.pf_flip:
    lea rdi, [flip_cmd]
    xor eax, eax
    mov ecx, 3
    rep stosq
    mov eax, [drm_chosen_crtc]
    mov [flip_cmd + 0], eax
    mov eax, [cur_front_fbid]
    mov [flip_cmd + 4], eax
    mov dword [flip_cmd + 8], DRM_MODE_PAGE_FLIP_EVENT
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_PAGE_FLIP
    lea rdx, [flip_cmd]
    syscall
    test rax, rax
    js  .pf_setcrtc_fb                  ; flip refused → SETCRTC fallback
    call wait_flip
    jmp .pf_swap
.pf_setcrtc_fb:
    call drm_reassert
.pf_swap:
    xor dword [back_idx], 1
    mov eax, [back_idx]
    mov rax, [db_addr + rax*8]
    mov [fb_addr], rax
    xor eax, eax
.pf_out:
    pop r12
    pop rbx
    ret

; wait_flip — poll the drm fd (≤500 ms) for the flip-complete event, drain it.
wait_flip:
    mov eax, [drm_fd]
    mov [drm_pollfd], eax
    mov word [drm_pollfd + 4], 1        ; POLLIN
    mov word [drm_pollfd + 6], 0
    mov rax, SYS_POLL
    lea rdi, [drm_pollfd]
    mov esi, 1
    mov edx, 500
    syscall
    test rax, rax
    jle .wf_out                         ; timeout/err — carry on regardless
    mov rax, SYS_READ
    mov rdi, [drm_fd]
    lea rsi, [ev_buf]
    mov edx, 24*32
    syscall
.wf_out:
    ret

; drm_reassert — SETCRTC cur_front_fbid (first bind, suspend/resume, flip
; fallback).
drm_reassert:
    mov eax, [drm_chosen_conn]
    mov [drm_set_conn_id], eax
    lea rdi, [drm_crtc_set]
    xor eax, eax
    mov ecx, 13
    rep stosq
    lea rax, [drm_set_conn_id]
    mov [drm_crtc_set + 0], rax
    mov dword [drm_crtc_set + 8], 1
    mov eax, [drm_chosen_crtc]
    mov [drm_crtc_set + 12], eax
    mov eax, [cur_front_fbid]
    mov [drm_crtc_set + 16], eax
    mov dword [drm_crtc_set + 32], 1    ; mode_valid
    lea rsi, [drm_modes_buf]
    lea rdi, [drm_crtc_set + 36]
    mov ecx, 17
    rep movsd
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_SETCRTC
    lea rdx, [drm_crtc_set]
    syscall
    ret

; drm_teardown — restore CRTC, then RMFB + munmap + DESTROY both buffers,
; DROP_MASTER, close.
drm_teardown:
    push rbx
    ; restore original CRTC
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_SETCRTC
    lea rdx, [drm_crtc_save]
    syscall
    xor ebx, ebx
.td_loop:
    cmp ebx, 2
    jge .td_done
    ; RMFB
    mov eax, [db_fbid + rbx*4]
    mov [drm_dumb_destroy], eax
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_RMFB
    lea rdx, [drm_dumb_destroy]
    syscall
    ; munmap
    mov rax, SYS_MUNMAP
    mov rdi, [db_addr + rbx*8]
    mov rsi, [drm_dumb_size]
    syscall
    ; DESTROY_DUMB
    mov eax, [db_handle + rbx*4]
    mov [drm_dumb_destroy], eax
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_DESTROY_DUMB
    lea rdx, [drm_dumb_destroy]
    syscall
    inc ebx
    jmp .td_loop
.td_done:
    ; DROP_MASTER + close
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_DROP_MASTER
    xor edx, edx
    syscall
    mov rax, SYS_CLOSE
    mov rdi, [drm_fd]
    syscall
    pop rbx
    ret

; drm_try_open — /dev/dri/card0..9, first that opens. rax = fd or -1.
drm_try_open:
    push rbx
    xor ebx, ebx
.dt_loop:
    cmp ebx, 10
    jge .dt_miss
    lea rdi, [drm_card_path]
    mov dword [rdi], '/dev'
    mov dword [rdi+4], '/dri'
    mov dword [rdi+8], '/car'
    mov byte [rdi+12], 'd'
    mov eax, ebx
    add al, '0'
    mov [rdi+13], al
    mov byte [rdi+14], 0
    mov rax, SYS_OPEN
    mov esi, O_RDWR
    xor edx, edx
    syscall
    test rax, rax
    jns .dt_ok
    inc ebx
    jmp .dt_loop
.dt_ok:
    pop rbx
    ret
.dt_miss:
    mov rax, -1
    pop rbx
    ret

; drm_get_resources — GETRESOURCES twice (counts then arrays). rax=0/-1.
drm_get_resources:
    lea rdi, [drm_res_buf]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_GETRESOURCES
    lea rdx, [drm_res_buf]
    syscall
    test rax, rax
    js  .dg_err
    ; cap + point arrays
    mov eax, [drm_res_buf + 32]
    cmp eax, DRM_MAX_IDS
    jbe .dg_fb
    mov eax, DRM_MAX_IDS
.dg_fb:
    mov [drm_res_buf + 32], eax
    lea rax, [drm_fb_ids]
    mov [drm_res_buf + 0], rax
    mov eax, [drm_res_buf + 36]
    cmp eax, DRM_MAX_IDS
    jbe .dg_c
    mov eax, DRM_MAX_IDS
.dg_c:
    mov [drm_res_buf + 36], eax
    lea rax, [drm_crtc_ids]
    mov [drm_res_buf + 8], rax
    mov eax, [drm_res_buf + 40]
    cmp eax, DRM_MAX_IDS
    jbe .dg_n
    mov eax, DRM_MAX_IDS
.dg_n:
    mov [drm_res_buf + 40], eax
    lea rax, [drm_conn_ids]
    mov [drm_res_buf + 16], rax
    mov eax, [drm_res_buf + 44]
    cmp eax, DRM_MAX_IDS
    jbe .dg_e
    mov eax, DRM_MAX_IDS
.dg_e:
    mov [drm_res_buf + 44], eax
    lea rax, [drm_enc_ids]
    mov [drm_res_buf + 24], rax
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_GETRESOURCES
    lea rdx, [drm_res_buf]
    syscall
    test rax, rax
    js  .dg_err
    xor eax, eax
    ret
.dg_err:
    mov rax, -1
    ret

; drm_find_connector — first connected with modes. rax=1 found (r12d = id,
; drm_conn_buf + drm_modes_buf[0] valid), rax=0 none.
drm_find_connector:
    push rbx
    push r13
    mov r13d, [drm_res_buf + 40]
    xor ebx, ebx
.df_loop:
    cmp ebx, r13d
    jge .df_none
    mov eax, [drm_conn_ids + rbx*4]
    mov r12d, eax
    lea rdi, [drm_conn_buf]
    xor eax, eax
    mov ecx, 10
    rep stosq
    mov [drm_conn_buf + 32], dword DRM_MAX_MODES
    mov [drm_conn_buf + 36], dword DRM_MAX_PROPS
    mov [drm_conn_buf + 40], dword DRM_MAX_IDS
    mov [drm_conn_buf + 48], r12d
    lea rax, [drm_enc_arr]
    mov [drm_conn_buf + 0], rax
    lea rax, [drm_modes_buf]
    mov [drm_conn_buf + 8], rax
    lea rax, [drm_props_arr]
    mov [drm_conn_buf + 16], rax
    lea rax, [drm_propvals_arr]
    mov [drm_conn_buf + 24], rax
    mov rax, SYS_IOCTL
    mov rdi, [drm_fd]
    mov esi, DRM_IOCTL_MODE_GETCONNECTOR
    lea rdx, [drm_conn_buf]
    syscall
    test rax, rax
    js  .df_skip
    mov eax, [drm_conn_buf + 60]
    cmp eax, DRM_MODE_CONNECTED
    jne .df_skip
    mov eax, [drm_conn_buf + 32]
    test eax, eax
    jz  .df_skip
    mov eax, 1
    pop r13
    pop rbx
    ret
.df_skip:
    inc ebx
    jmp .df_loop
.df_none:
    xor eax, eax
    pop r13
    pop rbx
    ret

; ============================================================================
; fbtest — anon 1920x1200 buffer instead of DRM; dump raw for PNG conversion.
; ============================================================================
fbtest_init:
    mov dword [fb_w], 1920
    mov dword [fb_h], 1200
    mov dword [fb_pitch], 1920*4
    mov qword [fb_size], 1920*1200*4
    mov rax, SYS_MMAP
    xor edi, edi
    mov rsi, [fb_size]
    mov edx, PROT_RW
    mov r10d, MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1
    xor r9d, r9d
    syscall
    mov [fb_addr], rax
    ret

fbtest_dump:
    push rbx
    mov rax, SYS_OPEN
    lea rdi, [path_fbtest_out]
    mov esi, O_WRONLY | O_CREAT | O_TRUNC
    mov edx, 0o644
    syscall
    test rax, rax
    js  .fd_done
    mov rbx, rax
    mov rax, SYS_WRITE
    mov rdi, rbx
    mov rsi, [fb_addr]
    mov rdx, [fb_size]
    syscall
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.fd_done:
    pop rbx
    ret

; ============================================================================
; small helpers
; ============================================================================
; streq_cstr — rdi, rsi NUL-terminated. ZF=1 if equal.
streq_cstr:
    mov al, [rdi]
    mov cl, [rsi]
    cmp al, cl
    jne .sq_ne
    test al, al
    jz  .sq_eq
    inc rdi
    inc rsi
    jmp streq_cstr
.sq_eq:
    xor eax, eax                        ; sets ZF
    ret
.sq_ne:
    or eax, 1                           ; clears ZF
    ret

; u32_to_ascii — eax = number, rdi = dest. Writes decimal, returns rdi past.
u32_to_ascii:
    push rbx
    push r12
    lea rbx, [rsp - 40]                 ; red-zone scratch
    lea r12, [rbx + 20]                 ; write backwards from here
    mov byte [r12], 0
    mov ecx, 10
    test eax, eax
    jnz .ua_loop
    dec r12
    mov byte [r12], '0'
    jmp .ua_copy
.ua_loop:
    xor edx, edx
    div ecx
    dec r12
    add dl, '0'
    mov [r12], dl
    test eax, eax
    jnz .ua_loop
.ua_copy:
    mov al, [r12]
    test al, al
    jz  .ua_done
    mov [rdi], al
    inc rdi
    inc r12
    jmp .ua_copy
.ua_done:
    pop r12
    pop rbx
    ret

; write_stderr — rsi = buf, rdx = len.
write_stderr:
    mov rax, SYS_WRITE
    mov edi, 2
    syscall
    ret

; write_cstr_stderr — rsi = NUL-terminated string.
write_cstr_stderr:
    push rbx
    mov rbx, rsi
    xor edx, edx
.wc_len:
    cmp byte [rbx + rdx], 0
    je  .wc_emit
    inc edx
    jmp .wc_len
.wc_emit:
    call write_stderr
    pop rbx
    ret

; write_u32_stderr — eax = number, decimal to stderr.
write_u32_stderr:
    lea rdi, [lognum_buf]
    call u32_to_ascii
    lea rsi, [lognum_buf]
    mov rdx, rdi
    sub rdx, rsi
    jmp write_stderr
