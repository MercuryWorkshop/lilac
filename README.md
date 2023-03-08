# policyeditor
it works lmao

## build instructions
 - build `boringssl` - source included just clear `boringssl/build` folder and then install to `boringssl/install`
 - build the protobuf files - `protoc -I proto proto/* --cpp_out=.`
 - run `make`

## run instructions
 - change the release channel to `testimage-channel` in `/etc/lsb-release`
 - add `--disable-policy-key-verification` to command line flags
 - run policyeditor on a `policy.*` in `/var/lib/devicesettings`
 - overwrite policies and `owner.key` (`owner.key` is saved as `<filename>.key`)
