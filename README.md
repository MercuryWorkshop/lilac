# lilac
it works lmao

## build instructions
 - build `boringssl` - source included just clear `boringssl/build` folder and then install to `boringssl/install`
 - install `protobuf`
 - build the protobuf files - `protoc -I proto proto/* --cpp_out=.`
 - run `make`

## run instructions
 - change the release channel to `testimage-channel` in `/etc/lsb-release`
 - add `--disable-policy-key-verification` to command line flags
 - run policyeditor on a `policy.*` in `/var/lib/devicesettings`
 - overwrite policies and `owner.key` (`owner.key` is saved as `<filename>.key`)
 
## notes
 - you probably need to keep wifi off / fake network error / overwrite policies and restart ui for this to persist
 - policies sync every time chrome starts meaning `restart ui` will reload policies + try to fetch them
 - protobuf bindings and even the editor may need to be adjusted for different chrome versions i.e. 81 has a completely different policy blob layout which might not allow this editing
