<img src="Lilac.png" alt="Lilac">

> [!IMPORTANT]  
> Protobuf bindings may need changes for different Chrome versions due to different policy blob layouts, which could prevent Lilac from working correctly.

## What is it?
Lilac is a device policy editor for ChromeOS that exploits a flag called `--disable-policy-key-verification`. When used, the flag disables the verification of the policy blob's signature, allowing it to be modified.

[You can view the original blog post here](https://www.r58playz.dev/post/lilac-the-device-policy-story)

## Building Lilac
- Clone the repo by running `git clone https://github.com/mercuryworkshop/lilac.git`
- Install `protobuf` using the package manager of your choice (`yay, apt, etc`)
- Compile `boringssl` by navigating from your home directory to `lilac/boringssl/build` and run:
<ul>
> ```
> cmake .. -DCMAKE_INSTALL_PREFIX=/path/to/lilac/boringssl/install -DBUILD_SHARED_LIBS=on
> make
> make install
> ```
</ul>
- Move back to the lilac directory and compile protobuf by running `protoc proto/* -Iproto --cpp_out=. `
- Run `make` to finish building Lilac

If you get undefined symbol errors, you may need to export `LD_LIBRARY_PATH="boringssl/install/lib"`.

## Running Lilac
 - Change the release channel to `testimage-channel` by editing `/etc/lsb-release`
 - Add the `--disable-policy-key-verification` flag to `/etc/chrome_dev.conf` and then run `sudo restart ui`
 - Run policyeditor on a `policy.*` in `/var/lib/devicesettings`
 - Overwrite policies and `owner.key` (saved as `<filename>.key`)
