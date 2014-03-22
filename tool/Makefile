all:       clean depends build       bundle
all-drone: clean depends build-drone bundle-drone


clean:
	-rm -rf ../out
	-rm ../test/all_client_tests.dart.js
	-rm ../test/all_client_tests.dart.js.deps
	-rm ../test/all_client_tests.dart.js.map
	-rm ../test/all_client_tests.dart.precompiled.js


depends:
	cd ..; pub get; cd tool


build:       test       doc
build-drone: test-drone doc-drone


test:       test-client test-server
test-drone:             test-server


test-server: depends
	@echo "********************************************************************************"
	@echo "RUNNING SERVER TESTS"
	@echo "********************************************************************************"

	dart ../test/all_server_tests.dart


test-client: depends
	@echo "********************************************************************************"
	@echo "RUNNING CLIENT TESTS"
	@echo "********************************************************************************"

	dart2js ../test/all_client_tests.dart -o ../test/all_client_tests.dart.js
	open ../test/all_client_tests.html


doc:       doc-drone
doc-drone: depends
	@echo "********************************************************************************"
	@echo "MAKING DOCUMENTATION"
	@echo "********************************************************************************"

	docgen  --start-page=cipher \
                --package-root=../packages \
                --compile \
                ../lib/cipher.dart

	-rm -rf ../out/doc
	mkdir -p ../out
	mv ./dartdoc-viewer/client/out/web ../out/doc
	rm -rf ./dartdoc-viewer


bundle:       bundle-package       bundle-doc
bundle-drone: bundle-package-drone bundle-doc 


bundle-package:       test bundle-package-drone
bundle-package-drone: 
	@echo "********************************************************************************"
	@echo "MAKING PACKAGE BUNDLE"
	@echo "********************************************************************************"

	-rm ../out/bundle/cipher.tar.gz
	mkdir -p ../out/bundle

	tar -c -z -C .. --exclude packages -f ../out/bundle/cipher.tar.gz LICENSE README.md changelog.md pubspec.yaml benchmark/ lib/ licenses/ test/ tool/


bundle-doc: doc
	@echo "********************************************************************************"
	@echo "MAKING DOC BUNDLE"
	@echo "********************************************************************************"

	-rm ../out/bundle/cipher-doc.tar.gz
	mkdir -p ../out/bundle

	tar -c -z -C../out/doc -f ../out/bundle/cipher-doc.tar.gz .


deploy: deploy-doc deploy-pub


deploy-doc: doc
	@echo "********************************************************************************"
	@echo "DEPLOYING DOC TO GITHUB'S GH-PAGES"
	@echo "********************************************************************************"


deploy-pub: test
	@echo "********************************************************************************"
	@echo "DEPLOYING TO PUB"
	@echo "********************************************************************************"

