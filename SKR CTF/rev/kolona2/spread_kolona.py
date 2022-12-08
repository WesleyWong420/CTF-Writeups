#kolona_genome = open('MT568643', 'r').read()
#kolona_rna = [
 #9728, 9150, 9459, 25263, 1634, 27368, 11779, 19149, 9629, 2721]
#kolona_rna2 = [5676, 10615, 13415, 16286, 17093, 13804, 26647, 26800, 4547, 13208]
#original_virus = open('original_virus', 'r').read()
#evolve_virus = ''
#for i in range(len(original_virus)):
    #evolve_virus += chr((ord(original_virus[i]) - ord(kolona_genome[kolona_rna[(i % 10)]]) - ord(kolona_genome[kolona_rna2[(i % 10)]])) % 256)

#print(evolve_virus)

#kolona_genome = open("MT568643",'r').read()
#kolona_rna1 = [23345, 11951, 3108, 5530, 21395, 4536, 27288, 1593, 15001, 3441, 21401, 16319, 3268, 24970, 25483, 26318, 3451, 19165, 23997, 9356]
#kolona_rna2 = [26841, 22129, 29143, 13838, 29641, 28796, 11242, 6388, 11659, 19381, 11479, 15576, 25715, 13948, 8014, 6941, 23751, 11716, 22374, 21328]
#evolved_virus = open("evolved_virus",'r').read()
#code = ""

#for i in range(len(evolved_virus)):
        #code += chr((ord(evolved_virus[i]) - ord(kolona_genome[kolona_rna1[i % 20]]) - ord(kolona_genome[kolona_rna2[i % 20]])) % 256)

#print(code)

import random
flag = open("flag.png","r")
kolona = open("flag.kolona","w+")
key = "SARS-CoV-2"
# Prevent Reverse Engineering!
random_num = random.randint(1,6666)

for i,c in enumerate(flag.read()):
        kolona.write(chr((ord(c) + ord(key[i % len(key)]) + random_num) % 256))
        # (ord(c) + ord(key[i % len(key)]) + random_num) % 256 = (((ord(c) + ord(key[i % len(key)])) % 256) + (random_num % 256)) % 256

