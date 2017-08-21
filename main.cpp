#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// stringification
#define str(s) #s

void print_error(const char *desc, DWORD errcode) {
	LPSTR errorText = NULL;

	FormatMessageA(
		// use system message tables to retrieve error text
		FORMAT_MESSAGE_FROM_SYSTEM
		// allocate buffer on local heap for error text
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		// Important! will fail otherwise, since we're not 
		// (and CANNOT) pass insertion parameters
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
		errcode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		errorText,  // output 
		0, // minimum size for output buffer
		NULL);   // arguments - see note 

	if (errorText != NULL) {
		if (desc == NULL) desc = "Error";
		if (errorText[strlen(errorText) - 1] == '\n') errorText[strlen(errorText) - 1] = '\0';
		if (errorText[strlen(errorText) - 1] == '\r') errorText[strlen(errorText) - 1] = '\0';
		fprintf(stderr, "%s: %08X: %s\n", desc, errcode, errorText);
		// release memory allocated by FormatMessage()
		LocalFree(errorText);
	}
}

#define GET_MITIGATION(proc, p, b, s) \
    if (!GetProcessMitigationPolicy((proc), (p), (b), (s))) { \
        if (0) { print_error(str(p), GetLastError()); } \
	    } else

void print_mitigations(HANDLE hProc) {

	PROCESS_MITIGATION_DEP_POLICY                       dep = { 0 };
	PROCESS_MITIGATION_ASLR_POLICY                      aslr = { 0 };
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY				dynamic_code = { 0 };
	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY       strict_handle_check = { 0 };
	PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY       system_call_disable = { 0 };
	PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY   extension_point_disable = { 0 };
	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY		cfg = { 0 };
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY			signature = { 0 };
	PROCESS_MITIGATION_FONT_DISABLE_POLICY				font = { 0 };
	PROCESS_MITIGATION_IMAGE_LOAD_POLICY				image_load = { 0 };
	ULONG64												mitigation_options = { 0 };

	GET_MITIGATION(hProc, ProcessDEPPolicy, &dep, sizeof(dep)) {
		printf("ProcessDEPPolicy\n");
		printf(" Enable                                     %u\n", dep.Enable);
		printf(" DisableAtlThunkEmulation                   %u\n", dep.DisableAtlThunkEmulation);
		printf(" Permanent                                  %u\n", dep.Permanent);
	}

	GET_MITIGATION(hProc, ProcessASLRPolicy, &aslr, sizeof(aslr)) {
		printf("ProcessASLRPolicy\n");
		printf(" EnableBottomUpRandomization                %u\n", aslr.EnableBottomUpRandomization);
		printf(" EnableForceRelocateImages                  %u\n", aslr.EnableForceRelocateImages);
		printf(" EnableHighEntropy                          %u\n", aslr.EnableHighEntropy);
		printf(" DisallowStrippedImages                     %u\n", aslr.DisallowStrippedImages);
	}

	GET_MITIGATION(hProc, ProcessDynamicCodePolicy, &dynamic_code, sizeof(dynamic_code)) {
		printf("ProcessDynamicCodePolicy\n");
		printf(" ProhibitDynamicCode                        %u\n", dynamic_code.ProhibitDynamicCode);
		printf(" AllowThreadOptOut                          %u\n", dynamic_code.AllowThreadOptOut);
//		printf(" AllowRemoteDowngrade  		                %u\n", dynamic_code.AllowRemoteDowngrade);
	}

	GET_MITIGATION(hProc, ProcessStrictHandleCheckPolicy, &strict_handle_check, sizeof(strict_handle_check)) {
		printf("ProcessStrictHandleCheckPolicy\n");
		printf(" RaiseExceptionOnInvalidHandleReference     %u\n", strict_handle_check.RaiseExceptionOnInvalidHandleReference);
		printf(" HandleExceptionsPermanentlyEnabled         %u\n", strict_handle_check.HandleExceptionsPermanentlyEnabled);
	}

	GET_MITIGATION(hProc, ProcessSystemCallDisablePolicy, &system_call_disable, sizeof(system_call_disable)) {
		printf("ProcessSystemCallDisablePolicy\n");
		printf(" DisallowWin32kSystemCalls                  %u\n", system_call_disable.DisallowWin32kSystemCalls);
	}

	GET_MITIGATION(hProc, ProcessExtensionPointDisablePolicy, &extension_point_disable, sizeof(extension_point_disable)) {
		printf("ProcessExtensionPointDisablePolicy\n");
		printf(" DisableExtensionPoints                     %u\n", extension_point_disable.DisableExtensionPoints);
	}

	GET_MITIGATION(hProc, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)) {
		printf("ProcessControlFlowGuardPolicy\n");
		printf(" EnableControlFlowGuard                     %u\n", cfg.EnableControlFlowGuard);
//		printf(" EnableExportSuppression                    %u\n", cfg.EnableExportSuppression);
//		printf(" StrictMode									%u\n", cfg.StrictMode);
	}

	GET_MITIGATION(hProc, ProcessSignaturePolicy, &signature, sizeof(signature)) {
		printf("ProcessSignaturePolicy\n");
		printf(" MicrosoftSignedOnly	                    %u\n", signature.MicrosoftSignedOnly);
		printf(" StoreSignedOnly                            %u\n", signature.StoreSignedOnly);
		printf(" MitigationOptIn                            %u\n", signature.MitigationOptIn);
	}

	GET_MITIGATION(hProc, ProcessFontDisablePolicy, &font, sizeof(font)) {
		printf("ProcessFontPolicy\n");
		printf(" DisableNonSystemFonts	                    %u\n", font.DisableNonSystemFonts);
		printf(" AuditNonSystemFontLoading  	            %u\n", font.AuditNonSystemFontLoading);
	}

	GET_MITIGATION(hProc, ProcessImageLoadPolicy, &image_load, sizeof(image_load)) {
		printf("ProcessImageLoadPolicy\n");
		printf(" NoRemoteImages                             %u\n", image_load.NoRemoteImages);
		printf(" NoLowMandatoryLabelImages                  %u\n", image_load.NoLowMandatoryLabelImages);
		printf(" PreferSystem32Images                       %u\n", image_load.PreferSystem32Images);
	}

	GET_MITIGATION(hProc, ProcessMitigationOptionsMask, &mitigation_options, sizeof(mitigation_options)) {
		printf("ProcessMitigationOptionsMask\n");
		printf(" MitigationOptions                          %llx\n", mitigation_options);

		if (mitigation_options & PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE) {
			printf(" PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE\n");
		}

		if (mitigation_options & PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON) {
			printf(" PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON\n");
		}
		else if (mitigation_options & PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_OFF) {
			printf(" PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_OFF\n");
		}

		if (mitigation_options & PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON) {
			printf(" PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON\n");
		}
		else if (mitigation_options & PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_OFF) {
			printf(" PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_OFF\n");
		}

	}
}

void usage(const char *p) {
	printf("Usage: %s <pid>\n", p);
}

int main(int argc, char* argv[]) {
	DWORD pid = 0;
	HANDLE hProc;

	if (argc != 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	pid = strtoul(argv[1], NULL, 0);
	if (pid == 0) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
	if (hProc == NULL) {
		print_error("OpenProcess", GetLastError());
		return EXIT_FAILURE;
	}

	print_mitigations(hProc);

	CloseHandle(hProc);
	return EXIT_SUCCESS;
}