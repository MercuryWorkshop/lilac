# policyeditor
does not currently work, chrome refuses to load policy due to invalid signature

## potential run instructions
 - change the release channel to `testimage-channel` in `/etc/lsb-release`
 - add `--disable-policy-key-verification` to command line flags
 - run policyeditor on a `policy.*` in `/var/lib/devicesettings`
