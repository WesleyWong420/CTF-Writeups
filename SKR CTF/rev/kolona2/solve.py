import random

kolona = open("flag.kolona", 'r')
flag = open("flag.png", "w+")
key = "SARS-CoV-2"
random_num = 187

for i,c in enumerate(kolona.read()):
	for j in range (0, 256):
		result = (j + ord(key[i % len(key)]) + random_num) % 256
		if (result == ord(c)):
			flag.write(chr(j))

print(random_num)