LIBS = -lssl -lcrypto 
LDFLAGS = -L./boringssl/install/lib -L/usr/lib
CFLAGS = -I./boringssl/install/include -I/usr/include
CFLAGS_PBUF := $(shell pkg-config --cflags --libs protobuf)

lilac: private_membership.pb.o private_membership_rlwe.pb.o serialization.pb.o device_management_backend.pb.o policy_common_definitions.pb.o chrome_device_policy.pb.o lilac.cc
	g++ -std=c++17 $^ -o $@ $(CFLAGS) $(CFLAGS_PBUF) $(LDFLAGS) $(LIBS)
	strip $@

%.o: %.cc
	g++ $(CFLAGS) $(LDFLAGS) -c $(LIBS) $< -o $@

clean:
	rm *.o lilac
