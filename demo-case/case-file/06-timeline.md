# 06 — Timeline (UTC, 2026-03-14)

Entries marked **E1** come from the evidence file in this case. Other entries come from the other projects of the same fictional
scenario and show how the investigations connect. They are **not** contained in E1.

| Time (UTC) | Event | Source | Observed / inferred |
|---|---|---|---|
| 02:00 | Normal nightly SSH login of `svc-backup` from `backup01` using a public key | 02 `auth.log` | observed |
| 07:00 | Authorised scanner causes 7 failed SSH logins (false positive) | 02 `auth.log` | observed |
| 09:12 | External scanner `198.51.100.23` probes the WAN; blocked by the firewall | 03 firewall log | observed |
| 10:02–10:05 | `203.0.113.45` guesses SSH passwords against `web01` (about 56 failures) | 01 / 02 / 03 | observed |
| 10:06:41 | SSH login as `svc-backup` succeeds with a password from `203.0.113.45` | 02 `auth.log` | observed |
| 10:08–10:11 | `su` to `labadmin`, root shell with `sudo`, new account `support01` created and added to `sudo` | 02 `auth.log`, 01 auditd | observed |
| 10:15 | `web01` tries to reach WS01 on tcp/445 and tcp/3389; blocked by the DMZ-to-LAN rule | 03 firewall log | observed |
| **11:29:47** | **`Invoice_March.docm` opened by `HARBOR\jdoe`** | **E1** (artifact log at 0x1200); 01 Sysmon | observed |
| **11:30:14** | **Word starts `cmd.exe`, which starts PowerShell with an encoded command (hidden window)** | **E1** (log 0x1200; command line 0x7600); 01 Sysmon | observed |
| **11:30:16** | **PowerShell connects to `203.0.113.45:443`** | **E1**; 01 Sysmon; 03 firewall (egress allowed) | observed |
| **11:30:17** | **`harbor_update.js` created in `C:\Users\jdoe\AppData\Local\Temp`** | **E1**; 01 Sysmon | observed |
| **11:30:20** | **`wscript.exe` starts the script** | **E1**; 01 Sysmon | observed |
| **11:31–11:38** | **Connections to `203.0.113.45:443` about every 60 seconds** | **E1** (single line "repeats about every 60 seconds"); 01 Sysmon (eight events) | observed |
| 11:36:40 | `whoami`, `ipconfig`, `net user` run by the script (discovery, T1033/T1016/T1087) | **E1** (artifact log); 01 Sysmon | observed |
| 11:40 | Triage file handed to the analyst | Case notes | observed |

*Inference, not observation:* the SSH attack at 10:02 and the document at 11:29 come from the same address, which suggests a
common source. The evidence does not show that the document and the SSH attack were planned together.
