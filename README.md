# SOC Analyst Home Lab: Attack Simulation & Detection Engineering

## Objective

I set up this lab to get actual hands-on experience with cyberattacks and detection. Not just reading about it or passing a cert exam, but doing it. I wanted to attack a system, see what that looks like from the defender's side, and write rules to catch it.

## Tools Used

- LimaCharlie (EDR)
- Sliver C2 (command & control framework)
- Sysmon (Windows event logging)
- YARA (malware signature scanning)
- Windows VM (target)
- Ubuntu Server (attacker)

## Lab Setup

Two cloud-hosted VMs from Eric Capuano's SYWTBSA 2.0 course. Windows as the victim, Linux running Sliver as the attacker. I installed the LimaCharlie sensor on the Windows VM, set it up to pull Sysmon logs, and turned on the Sigma ruleset extension for baseline detections.

## C2 Implant Deployment

I generated a Sliver C2 implant on the Linux VM and served it to the Windows machine through a web server. Messed this up on the first try. I set up an HTTPS listener instead of HTTP and didn't realize it until I downloaded the implant on Windows, ran it, and nothing happened. No callback. Had to go back, kill that job, spin up an HTTP listener, generate a new payload, and do it again.

The second implant (SMALL_ADVERTISING.exe) connected fine. Full access to the Windows machine. Commands, processes, network connections, everything.

The first broken implant (MID_SIDECAR.exe) just sat in the Downloads folder doing nothing. This ended up mattering later.

## Credential Dumping

After getting into the system I escalated to SYSTEM privileges with Sliver's `getsystem` command, then dumped lsass.exe from memory using rundll32 and comsvcs.dll. This is a real credential theft technique. Went over to LimaCharlie and found the SENSITIVE_PROCESS_ACCESS event in the timeline showing exactly what happened.

## Writing Detection Rules

Built a D&R rule to detect the credential dumping by watching for processes accessing lsass.exe that aren't normal Windows processes. Tested it, it worked, moved on.

Then I wrote a rule for ransomware behavior. Specifically catching `vssadmin delete shadows /all`, which ransomware runs to wipe backup copies before encrypting files.

First version of the rule used `op: is` for the command line match. This means it needs the EXACT string to fire. It technically worked, but then I thought about it and realized that's a problem. If an attacker throws in an extra space, changes the casing, reorders arguments, it's a miss. So I changed it to `op: contains` and split it into separate checks for "delete", "shadows", and "/all". Way more resilient.

Also hit a YAML indentation error when I updated the rule which took me a minute to figure out. YAML does not forgive you.

## Ransomware Simulation

Downloaded a ransomware simulator (NextronSystems QuickBuck) to test my rules against something more realistic. It does the whole chain: fake macro execution, shadow copy deletion, file creation and encryption. My updated D&R rule caught the shadow copy deletion and killed it. Both the Sigma rules and my custom rule fired on the same events.

## YARA

Added NCSC-written YARA rules to LimaCharlie for detecting Sliver implants. These rules look for strings and byte patterns that end up inside Sliver binaries when they compile. Stuff like the path `/sliver/`, function names like `ScreenshotReq` and `KillSessionReq`, and raw machine code from specific Sliver functions.

Here's where it got interesting. I ran a YARA scan on the Downloads folder and it caught MID_SIDECAR.exe (the broken implant from my earlier mistake) but completely missed SMALL_ADVERTISING.exe (the one that was actually connected to the C2 and doing damage). Same framework, same size, but different build configs. The HTTPS build probably had different obfuscation than the HTTP one, which stripped out the strings the YARA rule was looking for.

So the file that got flagged was the harmless one. The actual threat was invisible to that scan. If I was a real analyst and I only looked at what YARA caught, I would have missed the real implant. That one stuck with me.

## Automated Scanning

Set up D&R rules to auto-scan any process launched from the Downloads directory with YARA. Killed the Sliver implant, relaunched it, and watched the detection chain fire: "Execution from Downloads directory" first, then "YARA Detection in Memory" confirming Sliver in the running process. That part worked.

Tried to do the same thing for new files landing in Downloads (NEW_DOCUMENT events) but the events were never generated. Dug into it pretty deep. Checked Sysmon config, confirmed FileCreate was set to monitor Downloads, checked FIM rules in LimaCharlie, tried different file operations. Nothing. Ended up being a sensor-level ingestion issue with the cloud VM setup, not a rule problem. Logged it and moved on.

## What I Took Away From This

Exact-match rules are fragile. I saw it firsthand when my `op: is` rule worked in a controlled test but would have failed against any attacker who varied their syntax even slightly. `op: contains` with individual keyword checks is the move.

The YARA thing really got me. Two Sliver implants built slightly differently, one gets caught and one doesn't. You can't rely on a single detection method. You need layers. YARA for signatures, D&R rules for behavior, Sigma for known patterns, and an analyst who actually reads the timeline instead of just closing whatever alert popped up.

The stuff that broke taught me more than the stuff that worked. Debugging YAML errors, troubleshooting missing events, figuring out why one implant got detected and the other didn't. That's closer to what actual SOC work looks like than following a tutorial step by step.

I also think about it like gaming. Red team should always be trying to break what blue team built. That push and pull is what makes both sides better. Every bypass is a chance to build a better detection. Every detection is a puzzle for the red team to solve. That cycle is what makes this field interesting to me.

## What I'd Do Next

- Figure out the NEW_DOCUMENT issue. Probably needs Sysmon Event ID 11 tuning or a different event name in LimaCharlie
- Write rules for the other detections that fired (Suspicious Microsoft Office Child Process, Sysmon File Executable Creation)
- Try writing a YARA rule from scratch instead of using pre-built ones
- Add response actions beyond reporting. Auto-isolate the host, kill the process tree, send an alert

## Credit

Based on Eric Capuano's "So You Want to Be a SOC Analyst?" 2.0 course. He's a SANS instructor and runs Recon InfoSec.
