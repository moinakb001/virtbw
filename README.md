# virtbw: Virtual FIDO with Bitwarden passkeys

This is a fork of [Virtual FIDO](https://github.com/bulwarkid/virtual-fido) that adds a read-only
[Bitwarden](https://bitwarden.com) backend: the virtual USB security key logs in with the
passkeys already stored in your Bitwarden vault, so any browser or app that supports hardware
security keys can use them.

The backend only looks passkeys up. It never writes to the vault and stores nothing on disk:

-   Registering a new passkey (or U2F key) through the device is refused. Save passkeys with the
    Bitwarden apps or browser extension instead.
-   Signature counters are not updated. Passkeys created by Bitwarden use a counter of 0, which
    relying parties treat as "no counter", so this only matters for imported passkeys that use a
    non-zero counter.
-   PIN / user verification is not supported, because a PIN would have to be stored. Sites that
    require user verification will not accept the device.
-   Every login is approved in the terminal. Bitwarden's master password re-prompt setting is
    not enforced beyond that approval.

## Bitwarden usage

Install the [Bitwarden CLI](https://bitwarden.com/help/cli/) and unlock your vault. Then either:

-   **`cli` backend (default):** export the session key and let `virtbw` run `bw` for each lookup.

    ```sh
    export BW_SESSION="$(bw unlock --raw)"
    go run ./cmd/virtbw list    # show the passkeys that will be offered
    go run ./cmd/virtbw start   # attach the virtual security key
    ```

-   **`serve` backend:** run `bw serve` (the Vault Management API) and point `virtbw` at it.
    Lookups are faster because no `bw` process is started per request.

    ```sh
    bw serve --port 8087 &
    go run ./cmd/virtbw --backend serve --serve-url http://localhost:8087 start
    ```

On Linux and Windows the device is attached over USB/IP. On Linux, load `vhci-hcd` first and run
`start` with `sudo` (keep `BW_SESSION` with `sudo -E`), as described in the demo instructions
below.

### macOS

On macOS, `virtbw` creates a virtual HID security key with IOKit's `IOHIDUserDevice` (macOS
10.15+), so browsers and other apps that talk to USB security keys can see it. No driver or
USB/IP is involved.

macOS only lets a process create that device if its code signature carries the
`com.apple.developer.hid.virtual.device` entitlement, which needs Apple's approval:

1. In an Apple Developer Program account, request the "HID Virtual Device" capability
   (Certificates, Identifiers & Profiles → Identifiers → your App ID → Capability Requests tab).
   Approval can take weeks.
2. Once it is granted, enable it on an App ID (e.g. `com.yourname.virtbw`) and create a macOS
   development provisioning profile for that App ID and your Mac.
3. Build and sign the app bundle (needs Xcode command line tools):

    ```sh
    PROFILE=~/Downloads/virtbw.provisionprofile \
    IDENTITY="Apple Development: Your Name (ABCDE12345)" \
        scripts/macos-bundle.sh
    export BW_SESSION="$(bw unlock --raw)"
    build/virtbw.app/Contents/MacOS/virtbw start
    ```

Without a profile, the script signs ad hoc. macOS only runs that build if AMFI enforcement is
turned off, which requires disabling System Integrity Protection; that setup is untested.

The old DriverKit transport is still available with `go build -tags driverkit`, but it needs a
system extension installed (see `mac/USBDriver/README.md`).

Useful flags: `--cache-ttl` (how long the item list is reused, default 30s), `--sync=false`
(skip `bw sync` on start), `--verbose`. When several passkeys match a site, `virtbw` asks which
account to use.

The backend lives in the [`bitwarden`](./bitwarden) package. `bitwarden.NewClient` takes any
`bitwarden.Vault` (the `bw` CLI, `bw serve`, or your own) and returns a client for
`virtual_fido.Start`.

# Virtual FIDO

> Also check out [Bulwark Passkey](https://bulwark.id), a passkey manager based on VirtualFIDO that is currently in beta!

Virtual FIDO is a virtual USB device that implements the FIDO2/U2F protocol (like a YubiKey) to support 2FA and WebAuthN. Please note that this software is still in beta and under active development, so APIs may be subject to change.

## Features

-   Support for both Windows and Linux through USB/IP (Mac support coming later)
-   Connect using both U2F and FIDO2 protocols for both normal 2FA and WebAuthN
-   Store credentials in an encrypted format with a passphrase
-   Store credential data anywhere (example provided: a local file)
-   Generic approval mechanism for credential creation and login (example provided: terminal-based)

## How it works

Virtual FIDO creates a USB/IP server over local TCP to attach a virtual USB device. This USB device then emulates the USB/CTAP protocols to provide U2F/FIDO services to the host computer. In the demo, credentials created by the virtual device are stored in a local file, and approvals are done using the terminal.

## Demo Usage

Go to the [YubiKey test page](https://demo.yubico.com/webauthn-technical/registration) in order to test WebAuthN.

### Windows

Run `go run ./cmd/demo start` to attach the USB device. Run `go run ./cmd/demo --help` to see more commands, such as to list or delete credentials from the file.

### Linux

Note that this tool requires elevated permissions.

1. Run `sudo modprobe vhci-hcd` to load the necessary drivers.
2. Run `sudo go run ./cmd/demo start` to start up the USB device server. Authenticate when `sudo` prompts you; this is necessary to attach the device.
