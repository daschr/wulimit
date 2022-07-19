#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

#include <windows.h>
#include <psapi.h>
#include <winbase.h>
#include <securitybaseapi.h>
#include <sddl.h>
//#include <jobapi2.h>

#define STD_PROCLIST_ELEMS 4048

void print_last_error_message(void){
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
        fprintf(stderr, "[get_token_user] failed getting process token!\n");
        goto fail;
    }

    unsigned long needed_token_user_size;

    GetTokenInformation(token_handle, TokenUser, NULL, 0, &needed_token_user_size);

    if((!token_user)||*token_user_size<needed_token_user_size) {
        free(token_user);
        token_user=malloc(needed_token_user_size);
    }

    if(!GetTokenInformation(token_handle, TokenUser, token_user, needed_token_user_size, token_user_size)) {
        fprintf(stderr, "[get_token_user] failed getting token information!\n");
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

uint8_t is_process_owner(PTOKEN_USER token_user, unsigned long pid){
	HANDLE proc_handle=NULL;
    PTOKEN_USER proc_token_user=NULL;
    unsigned long proc_token_user_size=0;

    if((proc_handle=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, 0, pid))==NULL) {
//        fprintf(stderr, "[is_process_owner] failed getting process handle!\n");
        goto fail;
    }

    if((proc_token_user=get_token_user(proc_handle, proc_token_user, &proc_token_user_size))==NULL) {
//        fprintf(stderr, "[is_process_owner] failed getting user token!\n");
        goto fail;
    }
	
	uint8_t r=EqualSid(token_user->User.Sid, proc_token_user->User.Sid);

    CloseHandle(proc_handle);
    free(proc_token_user);

    return r;

fail:

//	print_last_error_message();

    if(proc_handle)
        CloseHandle(proc_handle);

    free(proc_token_user);

    return 0;

}

uint8_t get_username_from_ptoken_user(PTOKEN_USER token_user, wchar_t *username, unsigned long username_s,
									wchar_t *domain, unsigned long domain_s){
	
	SID_NAME_USE sidNameUse;
    if(!LookupAccountSidW(NULL, token_user->User.Sid, username, &username_s, domain, &domain_s, &sidNameUse)) {
        fprintf(stderr, "failed looking up username!\n");
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
        fprintf(stderr, "failed getting process handle!\n");
        goto fail;
    }

    if((token_user=get_token_user(proc_handle, token_user, &token_user_size))==NULL) {
        fprintf(stderr, "failed getting user token!\n");
        goto fail;
    }

    SID_NAME_USE sidNameUse;
    if(!LookupAccountSidA(NULL, token_user->User.Sid, owner, &owner_s, domain, &domain_s, &sidNameUse)) {
        fprintf(stderr, "failed loolking up account sid!\n");
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

uint8_t list_procs(void) {
    unsigned long procs_size=sizeof(DWORD)*STD_PROCLIST_ELEMS;
    unsigned long *procs=malloc(procs_size);
    unsigned long procs_size_used=0;

    if(!procs) return 0;
    if(!EnumProcesses(procs, procs_size, &procs_size_used)) {
        fprintf(stderr, "Error while enumerating processes!\n");
        return 0;
    }

    while(procs_size<=procs_size_used) {
        procs_size<<=1;
        free(procs);

        if(!(procs=malloc(procs_size))) return 0;

        if(!EnumProcesses(procs, procs_size, &procs_size_used)) {
            fprintf(stderr, "Error while enumerating processes!\n");
            return 0;
        }
    }

    procs_size_used/=sizeof(unsigned long);

	unsigned long current_user_token_size=0;
	PTOKEN_USER current_user_token=get_token_user(GetCurrentProcess(), NULL, &current_user_token_size);
	
    wchar_t owner[_MAX_PATH], domain[_MAX_PATH];
	wchar_t *sid;

	get_username_from_ptoken_user(current_user_token, owner, _MAX_PATH, domain, _MAX_PATH);
	ConvertSidToStringSidW(current_user_token->User.Sid, &sid);
	
	wprintf(L"Current SID: %ls@%ls (%ls)\n", owner, domain, sid);
	LocalFree(sid);

	
	printf("num_processes: %ld\n", procs_size_used);	
    for(unsigned long i=0; i<procs_size_used; ++i) {
		//get_process_owner(procs[i], owner, _MAX_PATH, domain, _MAX_PATH);
		if(is_process_owner(current_user_token, procs[i])){
            printf("%ld owned by current user\n", procs[i]);
    	}
/*else{
            printf("%ld owned by %s@%s\n", procs[i], owner, domain);
		}
*/
	}

    free(procs);

    return 1;
}

int main(int ac, char *as[]) {
    list_procs();
    return 0;
}
