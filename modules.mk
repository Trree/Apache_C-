mod_passauth.la: mod_passauth.slo provider.slo commands.slo config.slo libSQLiteCpp.a .libs/.version
	$(SH_LINK) -rpath $(libexecdir) mod_passauth.lo provider.lo config.lo commands.lo -lpcreposix -lpcre -L./third_party/SQLiteCpp/build -lSQLiteCpp -L./third_party/SQLiteCpp/build/sqlite3 -lsqlite3 -module -avoid-version -lstdc++

.libs/.version: .libs/mod_passauth.o
	@echo "Generate git info into binary file $@..."
	@LANG=C git describe --tags --always --dirty > $@
	@objcopy -R .git $<
	@objcopy -I `objdump -p $< | egrep -o "elf(.*)"` --add-section .git=.libs/.version $<

libSQLiteCpp.a:
	@sed -i "s/-Winit-self//g" third_party/SQLiteCpp/CMakeLists.txt
	@cd third_party/SQLiteCpp && sh build-koal.sh

acl_localdb_test.lo: tests/acl_localdb_test.cpp
	$(LIBTOOL) --mode=compile $(CXX_COMPILE) -D_PCREPOSIX_H -I./tests/googletest/include -I SQLiteCpp/include -I SQLiteCpp/sqlite3 -prefer-pic -c $< && touch $@

ifeq ($(HRP_VERSION),SSL6)
AP_LIBS = -L$(libdir) -lapr-1 -laprutil-1 -lpcreposix -lpcre
endif

acl_localdb_test: acl_localdb_test.lo provider.lo tests/googletest/lib/.libs/libgtest.a
	$(SH_LIBTOOL) --mode=link $(COMPILE) $(LT_LDFLAGS) $(ALL_LDFLAGS) $(SH_LDFLAGS) $(CORE_IMPLIB) $(SH_LIBS) -o $@ $^ $(AP_LIBS) -L./third_party/SQLiteCpp/build -lSQLiteCpp -L./third_party/SQLiteCpp/build/sqlite3 -lsqlite3 -ldl -lstdc++

tests/googletest/lib/.libs/libgtest.a:
	cd tests/googletest && autoreconf -fvi && ./configure && make

DISTCLEAN_TARGETS = modules.mk
shared =  mod_passauth.la

.PHONY: git-submodule-update
	cd .. && git submodule update --init
