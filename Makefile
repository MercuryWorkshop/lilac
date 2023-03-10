LIBS = -lprotobuf -lssl -lcrypto
LDFLAGS = -L./boringssl/install/lib -L/usr/lib
CFLAGS = -I./boringssl/install/include -I/usr/include

rafflesia: private_membership.pb.o private_membership_rlwe.pb.o serialization.pb.o device_management_backend.pb.o policy_common_definitions.pb.o chrome_device_policy.pb.o rafflesia.cc
#	x86_64-unknown-linux-gnu-g++ -std=c++17 $^ -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS) 
	g++ -std=c++17 $^ -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)
#	strip $@

%.o: %.cc
#	x86_64-unknown-linux-gnu-g++ $(CFLAGS) $(LDFLAGS) -c $(LIBS) $< -o $@
	g++ $(CFLAGS) $(LDFLAGS) -c $(LIBS) $< -o $@

clean:
	rm *.o patchpolicy
