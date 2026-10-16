/*
 * Minimal Win32-API shim to stand up Keysight's libHppVxi11Server.so.1.0 under
 * Linux/qemu-aarch64 WITHOUT linking the vendor libWinApi/libpalio (which drag in
 * hardware/systemd/aio). Implements only the WinApi symbols libHppVxi11Server
 * imports (see `nm -D -u`), with POSIX/pthreads semantics. Correctness is "good
 * enough to run the RPC server thread" — coarse global locking, real events/TLS.
 *
 * aarch64 LP64: HANDLE=void*, DWORD=uint32_t, BOOL=int, SIZE_T=size_t.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>

typedef void* HANDLE;
typedef uint32_t DWORD;
typedef int BOOL;

/* ---- unified TAGGED handle: a thread OR an event, never confused ----
 * (the old model returned (HANDLE)1 for threads and a struct ptr for events, so
 * WaitForSingleObject/CloseHandle on a thread handle dereferenced 0x1 -> rare,
 * non-reproducible segv under concurrency. Tagging removes that artifact class.) */
enum { HK_THREAD=1, HK_EVENT=2 };
struct whandle { int kind; pthread_t th; int joined; pthread_mutex_t m; pthread_cond_t c; int signaled; };

typedef DWORD (*THREAD_START)(void*);
struct thunk { THREAD_START start; void* param; };
static void* thread_trampoline(void* a){ struct thunk* t=a; DWORD r=t->start(t->param); free(t); return (void*)(uintptr_t)r; }
HANDLE CreateThread(void* attrs, size_t stack, THREAD_START start, void* param, DWORD flags, DWORD* tid){
    (void)attrs;(void)stack;(void)flags;
    struct thunk* t=malloc(sizeof *t); t->start=start; t->param=param;
    struct whandle* h=calloc(1,sizeof *h); h->kind=HK_THREAD;
    if(pthread_create(&h->th,NULL,thread_trampoline,t)!=0){ free(t); free(h); return NULL; }
    if(tid) *tid=(DWORD)(uintptr_t)h->th;
    return (HANDLE)h;
}
void RegisterThreadProcessNotifications(void){ /* no-op */ }
DWORD GetCurrentThreadId(void){ return (DWORD)(uintptr_t)pthread_self(); }
DWORD GetCurrentProcessId(void){ return (DWORD)getpid(); }

/* ---- critical sections: coarse single recursive mutex (enough to run) ---- */
static pthread_mutex_t g_cs = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
void InitializeCriticalSection(void* cs){ (void)cs; }
void DeleteCriticalSection(void* cs){ (void)cs; }
void EnterCriticalSection(void* cs){ (void)cs; pthread_mutex_lock(&g_cs); }
void LeaveCriticalSection(void* cs){ (void)cs; pthread_mutex_unlock(&g_cs); }

/* ---- events: manual-reset-ish events via mutex+cond, on the tagged handle ---- */
HANDLE CreateEvent(void* sa, BOOL manualReset, BOOL initial, const char* name){
    (void)sa;(void)manualReset;(void)name;
    struct whandle* e=calloc(1,sizeof *e); e->kind=HK_EVENT;
    pthread_mutex_init(&e->m,NULL); pthread_cond_init(&e->c,NULL);
    e->signaled=initial?1:0; return (HANDLE)e;
}
BOOL SetEvent(HANDLE h){ struct whandle* e=h; if(!e||e->kind!=HK_EVENT)return 0; pthread_mutex_lock(&e->m); e->signaled=1; pthread_cond_broadcast(&e->c); pthread_mutex_unlock(&e->m); return 1; }
BOOL ResetEvent(HANDLE h){ struct whandle* e=h; if(!e||e->kind!=HK_EVENT)return 0; pthread_mutex_lock(&e->m); e->signaled=0; pthread_mutex_unlock(&e->m); return 1; }
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT  0x102u
DWORD WaitForSingleObject(HANDLE h, DWORD ms){
    struct whandle* e=h; if(!e) return WAIT_OBJECT_0;
    if(e->kind==HK_THREAD){ if(!e->joined){ e->joined=1; pthread_join(e->th,NULL); } return WAIT_OBJECT_0; }
    pthread_mutex_lock(&e->m);
    if(ms==0xFFFFFFFFu){ while(!e->signaled) pthread_cond_wait(&e->c,&e->m); }
    else { struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); ts.tv_sec+=ms/1000; ts.tv_nsec+=(ms%1000)*1000000L; if(ts.tv_nsec>=1000000000L){ts.tv_sec++;ts.tv_nsec-=1000000000L;}
           while(!e->signaled){ if(pthread_cond_timedwait(&e->c,&e->m,&ts)!=0) break; } }
    DWORD r=e->signaled?WAIT_OBJECT_0:WAIT_TIMEOUT; pthread_mutex_unlock(&e->m); return r;
}
BOOL CloseHandle(HANDLE h){
    struct whandle* e=h; if(!e) return 1;
    if(e->kind==HK_THREAD){ if(!e->joined) pthread_detach(e->th); }
    else { pthread_mutex_destroy(&e->m); pthread_cond_destroy(&e->c); }
    free(e); return 1;
}

/* ---- TLS ---- */
static pthread_key_t g_keys[256]; static int g_nkeys=0; static pthread_mutex_t g_klock=PTHREAD_MUTEX_INITIALIZER;
DWORD TlsAlloc(void){ pthread_mutex_lock(&g_klock); int i=g_nkeys++; pthread_key_create(&g_keys[i],NULL); pthread_mutex_unlock(&g_klock); return (DWORD)i; }
BOOL  TlsFree(DWORD i){ (void)i; return 1; }
void* TlsGetValue(DWORD i){ return pthread_getspecific(g_keys[i]); }
BOOL  TlsSetValue(DWORD i, void* v){ return pthread_setspecific(g_keys[i],v)==0; }

/* ---- misc ---- */
void Sleep(DWORD ms){ usleep((useconds_t)ms*1000); }
void logMsgToEventViewer(const char* s){ (void)s; }
void logMsgToEventViewerEx(const char* s, int a, int b){ (void)s;(void)a;(void)b; }

/* safe-string shims (Annex K) -> standard equivalents */
int sprintf_s(char* b, size_t n, const char* fmt, ...){ va_list ap; va_start(ap,fmt); int r=vsnprintf(b,n,fmt,ap); va_end(ap); return r; }
int strcpy_s(char* d, size_t n, const char* s){ if(!d||!s||n==0) return 22; snprintf(d,n,"%s",s); return 0; }
struct tm;
int localtime_s(struct tm* out, const time_t* t){ return localtime_r(t,(void*)out)?0:1; }

/* case-insensitive + Annex-K string shims (added after runtime symbol-resolution loop) */
#include <strings.h>
int _stricmp(const char* a, const char* b){ return strcasecmp(a,b); }
int _strnicmp(const char* a, const char* b, size_t n){ return strncasecmp(a,b,n); }
int strnicmp(const char* a, const char* b, size_t n){ return strncasecmp(a,b,n); }
int strncpy_s(char* d, size_t dsz, const char* s, size_t count){
    if(!d||!s||dsz==0) return 22; size_t n=count<dsz-1?count:dsz-1; memcpy(d,s,n); d[n]='\0'; return 0; }
char* strtok_s(char* str, const char* delim, char** ctx){ return strtok_r(str,delim,ctx); }
