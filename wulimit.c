#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <getopt.h>

#include <windows.h>
#include <psapi.h>
#include <winbase.h>
#include <securitybaseapi.h>
#include <sddl.h>
//#include <jobapi2.h>

#define STD_PROCLIST_ELEMS 4048

#ifdef DEBUG
#define BLAME(X) fprintf(stderr, X)
#define print_last_error_message() _print_last_error_message()
#else
#define BLAME(X)
#define print_last_error_message()
#endif


void _print_last_error_message(void) {
    wchar_t *emsg=NULL;

    if(!FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0, (wchar_t *) &emsg, 0, NULL))
        fwprintf(stderr, L"[print_last_error_message] failed getting error message!\n");
    else
        fwprintf(stderr, L"GetLastError(): %ls\n", emsg);
    LocalFree(emsg);
}

PTOKEN_USER get_token_user(HANDLE proc_handle, PTOKEN_USER token_user, unsigned long *token_user_size) {
    HANDLE token_handle=NULL;

    if(!OpenProcessToken(proc_handle, TOKEN_READ, &token_handle)) {
        BLAME("[get_token_user] failed getting process token!\n");
        goto fail;
    }

    unsigned long needed_token_user_size;

    GetTokenInformation(token_handle, TokenUser, NULL, 0, &needed_token_user_size);

    if((!token_user)||*token_user_size<needed_token_user_size) {
        free(token_user);
        token_user=malloc(needed_token_user_size);
    }

    if(!GetTokenInformation(token_handle, TokenUser, token_user, needed_token_user_size, token_user_size)) {
        BLAME("[get_token_user] failed getting token information!\n");
        goto fail;
    }

    if(token_handle)
        CloseHandle(token_handle);

    return token_user;

fail:

    print_last_error_message();

    if(token_handle)
        CloseHandle(token_handle);

    return NULL;
}

uint8_t is_process_owner(PTOKEN_USER token_user, unsigned long pid) {
    HANDLE proc_handle=NULL;
    PTOKEN_USER proc_token_user=NULL;
    unsigned long proc_token_user_size=0;

    if((proc_handle=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, 0, pid))==NULL) {
        BLAME("[is_process_owner] failed getting process handle!\n");
        goto fail;
    }

    if((proc_token_user=get_token_user(proc_handle, proc_token_user, &proc_token_user_size))==NULL) {
        BLAME("[is_process_owner] failed getting user token!\n");
        goto fail;
    }

    uint8_t r=EqualSid(token_user->User.Sid, proc_token_user->User.Sid);

    CloseHandle(proc_handle);
    free(proc_token_user);

    return r;

fail:

    print_last_error_message();

    if(proc_handle)
        CloseHandle(proc_handle);

    free(proc_token_user);

    return 0;

}

uint8_t add_pid_to_job(HANDLE job, unsigned long pid) {
    HANDLE proc_handle=NULL;

    if((proc_handle=OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE, 0, pid))==NULL) {
        BLAME("[add_pid_to_job] failed getting process handle!\n");
        goto fail;
    }

    if(!AssignProcessToJobObject(job, proc_handle)) {
        BLAME("[add_pid_to_job] failed assiging process to job!\n");
        goto fail;
    }

    CloseHandle(proc_handle);

    return 1;

fail:

    print_last_error_message();

    if(proc_handle)
        CloseHandle(proc_handle);

    return 0;
}

uint8_t get_username_from_ptoken_user(PTOKEN_USER token_user, wchar_t *username, unsigned long username_s,
                                      wchar_t *domain, unsigned long domain_s) {

    SID_NAME_USE sidNameUse;
    if(!LookupAccountSidW(NULL, token_user->User.Sid, username, &username_s, domain, &domain_s, &sidNameUse)) {
        BLAME("failed looking up username!\n");
        print_last_error_message();
        return 0;
    }

    return 1;
}

uint8_t get_process_owner(unsigned long pid, char *owner, unsigned long owner_s,
                          char *domain, unsigned long domain_s) {

    HANDLE proc_handle=NULL;
    PTOKEN_USER token_user=NULL;
    unsigned long token_user_size=0;

    if((proc_handle=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, 0, pid))==NULL) {
        BLAME("failed getting process handle!\n");
        goto fail;
    }

    if((token_user=get_token_user(proc_handle, token_user, &token_user_size))==NULL) {
        BLAME("failed getting user token!\n");
        goto fail;
    }

    SID_NAME_USE sidNameUse;
    if(!LookupAccountSidA(NULL, token_user->User.Sid, owner, &owner_s, domain, &domain_s, &sidNameUse)) {
        BLAME("failed loolking up account sid!\n");
        goto fail;
    }

    if(proc_handle)
        CloseHandle(proc_handle);
    free(token_user);
    return 1;

fail:

    print_last_error_message();

    if(proc_handle)
        CloseHandle(proc_handle);

    free(token_user);

    return 0;
}

inline char *get_current_sid(void) {
    unsigned long current_user_token_size=0;
    char *sid;

    PTOKEN_USER current_user_token=get_token_user(GetCurrentProcess(), NULL, &current_user_token_size);
    ConvertSidToStringSidA(current_user_token->User.Sid, &sid);

    return sid;
}

uint8_t limit_procs(JOBOBJECT_EXTENDED_LIMIT_INFORMATION *limits) {
    char *sid;
    unsigned long current_user_token_size=0;
    PTOKEN_USER current_user_token=get_token_user(GetCurrentProcess(), NULL, &current_user_token_size);
    if(!current_user_token) return 0;
    ConvertSidToStringSidA(current_user_token->User.Sid, &sid);

#ifdef DEBUG
    printf("using JOBNAME: %s\n", sid);
#endif
    HANDLE job;
    if((job=CreateJobObjectA(NULL, sid))==NULL) {
        BLAME("[limit_procs] failed creating jobobject!\n");
        LocalFree(sid);
        return 0;
    }
    LocalFree(sid);

    // add processes to job

    unsigned long procs_size=sizeof(DWORD)*STD_PROCLIST_ELEMS;
    unsigned long *procs=malloc(procs_size);
    unsigned long procs_size_used=0;

    if(!procs) return 0;
    if(!EnumProcesses(procs, procs_size, &procs_size_used)) {
        BLAME("[limit_procs] Error while enumerating processes!\n");
        return 0;
    }

    while(procs_size<=procs_size_used) {
        procs_size<<=1;
        free(procs);

        if(!(procs=malloc(procs_size))) return 0;

        if(!EnumProcesses(procs, procs_size, &procs_size_used)) {
            BLAME("[limit_procs] Error while enumerating processes!\n");
            return 0;
        }
    }

    procs_size_used/=sizeof(unsigned long);

    for(unsigned long i=0; i<procs_size_used; ++i) {
        if(is_process_owner(current_user_token, procs[i])) {
#ifdef DEBUG
            printf("%ld owned by current user, adding to job\n", procs[i]);
#endif
            add_pid_to_job(job, procs[i]);
        }
    }

    free(current_user_token);
    free(procs);

    if(!SetInformationJobObject(job, JobObjectExtendedLimitInformation, limits,
                                sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))) {
        BLAME("[limit_procs] failed configuring limits!\n");
        return 0;
    }

    CloseHandle(job);
#ifdef DEBUG
    puts("limits set");
#endif
    return 1;
}

static inline void help_msg(const char *name) {
    fprintf(stderr, "Usage: %s -v [MB] -V [MB]\n", name);
    fprintf(stderr, "\t-v [mem] - per process max size [MB] of virtual memory; see win32 ProcessMemoryLimit\n"
            "\t-V [mem] - max size [MB] of virtual memory of the whole session; see win32 JobMemoryLimit\n");
}

int main(int ac, char *as[]) {
    if(ac<2) {
        help_msg(as[0]);
        return EXIT_FAILURE;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION *limits=malloc(sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
    memset(limits, 0, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
    limits->BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    int opt;
    while((opt=getopt(ac, as, "v:V:"))!=-1) {
        switch(opt) {
        case 'v':
            limits->ProcessMemoryLimit=strtoul(optarg, NULL,  10);
            limits->BasicLimitInformation.LimitFlags|=JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            break;
        case 'V':
            limits->JobMemoryLimit=strtoul(optarg, NULL,  10);
            limits->BasicLimitInformation.LimitFlags|=JOB_OBJECT_LIMIT_JOB_MEMORY;
            break;
        default:
            help_msg(as[0]);
            free(limits);
            return EXIT_FAILURE;
        }
    }

    limit_procs(limits);

    free(limits);
    return EXIT_SUCCESS;
}
