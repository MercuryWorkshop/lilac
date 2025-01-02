<img src="Lilac.png" alt="Lilac">

## What is it?
Lilac is a device policy editor for ChromeOS that exploits a flag called `--disable-policy-key-verification` in Chrome. When used, the flag disables the verification of the signature of the policy blob, allowing for the policy to be tampered with.

[You can view the original blog post here](https://www.r58playz.dev/post/lilac-the-device-policy-story)

## build instructions
 - build `boringssl` - source included just clear `boringssl/build` folder and then install to `boringssl/install`
 - install `protobuf`
 - build the protobuf files - `protoc -I proto proto/* --cpp_out=.`
 - run `make`

You may need to set `LD_LIBRARY_PATH=boringssl/install/lib` to run lilac.

## run instructions
 - change the release channel to `testimage-channel` in `/etc/lsb-release`
 - add `--disable-policy-key-verification` to command line flags (update: you only need to restart chrome with this flag once after you replace the policies)
 - run policyeditor on a `policy.*` in `/var/lib/devicesettings`
 - overwrite policies and `owner.key` (`owner.key` is saved as `<filename>.key`)
 
## notes
 - you probably need to keep wifi off / fake network error / overwrite policies and restart ui for this to persist
   - apparently not... i have had lilac edited policies with wifi on for multiple weeks, it may not show as online on gac when syncing policies due to a signature error because i overwrite the policy sig
 - policies sync every time chrome starts meaning `restart ui` will reload policies + try to fetch them
 - protobuf bindings and even the editor may need to be adjusted for different chrome versions i.e. 81 has a completely different policy blob layout which might not allow this editing
