ifeq ($(RATS_TLS_VERSION),)
$(error "Please run make package in the root directory")
endif

ifeq ($(RATS_TLS_MAINTAINER),)
$(error "Please run make package in the root directory")
endif

PROJECT := rats-tls
PROJECT_DIR := $(shell cd ../..; pwd)
RPMBUILD_DIR := $(shell mktemp -u /tmp/rpmbuild.XXXX)
RELEASE_TARBALL_FILE := $(RPMBUILD_DIR)/SOURCES/v$(RATS_TLS_VERSION).tar.gz
RELEASE_TARBALL_EXIST := $(shell if [ -f $(RELEASE_TARBALL_FILE) ]; then echo "y"; else echo "n"; fi;)

release-tarball:
ifneq ($(RELEASE_TARBALL_EXIST), y)
	@mkdir -p $(RPMBUILD_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@cp -r $(PROJECT_DIR) $(RPMBUILD_DIR)/SOURCES/$(PROJECT)-$(RATS_TLS_VERSION)
	@cd $(RPMBUILD_DIR)/SOURCES && tar -cvzf "v$(RATS_TLS_VERSION).tar.gz" $(PROJECT)-$(RATS_TLS_VERSION)
endif

rpm: rpm/rats_tls.spec release-tarball
	@cp rpm/rats-tls*-filelist $(RPMBUILD_DIR)/SOURCES
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba --define 'mode host' rpm/rats_tls.spec
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba --define 'mode occlum' rpm/rats_tls.spec
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba --define 'mode sgx' rpm/rats_tls.spec
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba --define 'mode tdx' rpm/rats_tls.spec
	@cp $(RPMBUILD_DIR)/RPMS/x86_64/*.rpm $(PROJECT_DIR)/$(PROJECT)
	@rm -rf $(RPMBUILD_DIR)
	@echo "the rpms of rats tls located in $(PROJECT_DIR)"

deb: deb/debian/changelog
	@cd deb && ./build.sh
	@echo "the debs of rats tls located in $(PROJECT_DIR)"

package: rpm/rats_tls.spec.in deb/debian/changelog.in
ifeq (/etc/debian_version, $(wildcard /etc/debian_version))
	date=`date "+%a, %d %b %Y %H:%M:%S"` && \
	sed "1i\rats-tls ($(RATS_TLS_VERSION)-1) unstable; urgency=low\n\n  * Update to version $(RATS_TLS_VERSION).\n\n -- $(RATS_TLS_MAINTAINER)  $$date +0000\n" deb/debian/changelog.in > deb/debian/changelog;
	make deb
else ifeq (/etc/redhat-release, $(wildcard /etc/redhat-release))
	sed 's/Version: %{RATS_TLS_VERSION}/Version: $(RATS_TLS_VERSION)/' rpm/rats_tls.spec.in > rpm/rats_tls.spec && egrep -q '^\* .+ - $(RATS_TLS_VERSION)' rpm/rats_tls.spec || { \
	date=`date "+%a %b %d %Y"` && \
	sed -i "/%changelog/a* $$date $(RATS_TLS_MAINTAINER) - $(RATS_TLS_VERSION)\n- Update to version $(RATS_TLS_VERSION)\n" rpm/rats_tls.spec; };
	make rpm
else
	@echo "error! don't support generating packages on this system"
endif

.PHONY: release-tarball rpm deb package
