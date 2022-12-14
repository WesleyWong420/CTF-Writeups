# DFIR 5

> **Challenge Description:** The SOC analyst reported that they have found some malicious activities. We assume that the attacker still exists in the compromised host. The attached artifact is one of the potential place to find the attacker's backdoor leftovers. Find me the backdoor! Provide the file name as flag.
>
> **Flag Format:** `ihack{name.ext}`

### Solution

The challenge description suggests that this is a WMI persistence.

Parse the given `OBJECTS.DATA` file using `PyWMIPersistenceFinder.py`.

```
┌──(kali💀JesusCries)-[~/Desktop/DFIR 5]
└─$ python2 PyWMIPersistenceFinder.py OBJECTS.DATA 

    Enumerating FilterToConsumerBindings...
    2 FilterToConsumerBinding(s) Found. Enumerating Filters and Consumers...

    Bindings:

        SCM Event Log Consumer-SCM Event Log Filter
                (Common binding based on consumer and filter names, possibly legitimate)
            Consumer: NTEventLogEventConsumer ~ SCM Event Log Consumer ~ sid ~ Service Control Manager

            Filter: 
                Filter name:  SCM Event Log Filter
                Filter Query: select * from MSFT_SCMEventLogEvent

        DataCleanup-Cleanup
            Consumer: 
                Consumer Type: CommandLineEventConsumer
                Arguments:     C:\Windows\System32\svchostss.exe
                Consumer Name: DataCleanup

            Filter: 
                Filter name:  Cleanup
                Filter Query: Close


            Filter: 
                Filter name:  Cleanup
                Filter Query: Create Mailslot


            Filter: 
                Filter name:  Cleanup
                Filter Query: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325


    Thanks for using PyWMIPersistenceFinder! Please contact @DavidPany with questions, bugs, or suggestions.

    Please review FireEye's whitepaper for additional WMI persistence details:
        https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
```

**Flag:** `ihack{svchostss.exe}`
