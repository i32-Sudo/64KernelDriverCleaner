# 64KernelDriverCleaner
A Kernel Driver that can be used for a cheat or malware base to circumvent common cache &amp; structure table checks. PsLoadedModuleList however requires a PG Bypass on (Some) Machines > 22H2 Win10, Not Win 11
```cpp
void CleanDriverSys(UNICODE_STRING driver_int, ULONG timeDateStamp) {
	if (clear::clearCache(driver_int, timeDateStamp) == 0) {
		log(_("PiDDB Cache Found and Cleared!"));
	}
	else {
		log(_("PiDDB Non-Zero"));
	}
	if (clear::clearHashBucket(driver_int) == 0) {
		log(_("HashBucket Found and Cleared!"));
	}
	else {
		log(_("HashBucket Non-Zero"));
	}
	if (clear::CleanMmu(driver_int) == 0) {
		log(_("MMU/MML Found and Cleaned!"));
	}
	else {
		log(_("MMU/MML Non-Zero"));
	}
}
```
