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
   - apparently not... i have had lilac edited policies with wifi on for multiple weeks, it may not show as online on gac when syncing policies due to a signature error because i overwrite the policy sig
 - policies sync every time chrome starts meaning `restart ui` will reload policies + try to fetch them
 - protobuf bindings and even the editor may need to be adjusted for different chrome versions i.e. 81 has a completely different policy blob layout which might not allow this editing


## writeup or something?
Ash has this amazing flag called `--disable-policy-key-verification` which seems to disable verifying policy signatures based on its name. After a look in the code, it actually disables verifying policy signatures' signatures (when Ash is running in a test image). I can use this along with a basic policy editor that Rory McNamara made (thanks rory once again!) to make a fake policy blob. After looking through the source once again to see how the unit tests make a policy signature, I can inject this into the policy blob to make a fake policy blob that Ash sees as a real one from the Google device management servers.

(this was my first writeup)
