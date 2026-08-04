### ` Overview - What it checks`

- SSH and authentication
- Perimeter and intrusion response
- Privilege and filesystem
- System state
- Performance

<img width="1197" height="685" alt="fronttvps" src="https://github.com/user-attachments/assets/1ba45a12-62ed-4571-8375-5f6143573d29" />


### ` Installation`

          git clone https://github.com/Alb4don/VPSSentinel.git
          
          cd vpssentinel
          
          pip install psutil   # optional, recommended
          
          python3 vps_sentinel.py

- On Windows, run from an elevated PowerShell or Command Prompt for full coverage of the privileged checks.


### ` Usage`

          python3 vps_sentinel.py                    | full audit, formatted report |
          sudo python3 vps_sentinel.py               | full audit including SUID scan and log review |
          python3 vps_sentinel.py --quick            | skips the full-filesystem SUID scan |
          python3 vps_sentinel.py --json             | JSON to stdout instead of the formatted report |
          python3 vps_sentinel.py --output report.json  | JSON written to file (in addition to formatted stdout) |
          python3 vps_sentinel.py --no-color         | disable ANSI colors, e.g. for log files |
          python3 vps_sentinel.py --no-banner        | suppress the ASCII banner |


### ` Disclaimer`

- This tool is under development and is being made available on an "as-is" basis.

- It may have some limitations, for example:

  - It doesn't remediate anything. It reports; you fix. There's no --fix flag and it won't touch your sshd_config or firewall rules.
  - The SUID baseline is a static list, not something derived per-distro.
  - A binary that's legitimate on your specific distribution but not in the baseline will get flagged for review even if it's fine.
  - Windows update detection depends on Microsoft.Update.Session COM being reachable, which can be blocked by WSUS policy or endpoint hardening.
  - The virtualization/VPS detection is heuristic once you're off systemd-detect-virt. DMI firmware strings and the CPU hypervisor flag are reliable signals in practice, but not a guarantee.
