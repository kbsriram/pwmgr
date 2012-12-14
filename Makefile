index.html: src/index.int src/header.txt src/footer.txt
	cat src/header.txt src/index.int src/footer.txt > index.html

src/index.int: src/index.txt lib/docmaker.jar
	java -jar lib/docmaker.jar -html src/index.txt > src/index.int
