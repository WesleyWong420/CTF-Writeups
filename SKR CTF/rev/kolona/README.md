# Kolona

### Solution
```
#!/usr/bin/env python2
import codecs

kolona = open("flag.kolona", 'r')
flag = open("flag.jpg", "w+")
key = "COVID-19"

for i,c in enumerate(kolona.read()):
	result = ord(c) ^ ord(key[i % len(key)])
	flag.write(chr(result))
```

**Flag:** `SKR{V1rus_1s_3verywhere_pl3453_st4y_4t_H0me}`
![Flag](./flag.jpg)
