all: scrypt vcrypt feistel

scrypt:
	javac scrypt.java
	echo '#!/bin/bash' > scrypt
	echo 'java scrypt "$$@"' >> scrypt
vcrypt:
	javac vcrypt.java
	echo '#!/bin/bash' > vcrypt
	echo 'java vcrypt "$$@"' >> vcrypt
feistel:
	javac feistel.java
	echo '#!/bin/bash' > feistel
	echo 'java feistel "$$@"' >> feistel
clean:
	rm -f *.class scrypt vcrypt feistel