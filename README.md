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
-   By default, every login is approved in the terminal and PIN / user verification is not
    supported. Chromium requires verification for discoverable passkeys on external keys,
    so this default cannot satisfy that flow.
-   `--trust-unlocked-vault` enables a compatibility mode without separate verification
    or login approval prompts. A successful live
    Bitwarden read authorizes the operation; GetInfo advertises `uv: true`, and requested
    UV is reported in the signed assertion. Presence also follows this authorization
    policy. These flags reflect trust in the unlocked vault, **not a fresh identity or
    presence check**. This is not a hardware-equivalent verification guarantee.
-   In that mode, locked or unreachable vaults fail closed even with a warm cache. When
    multiple passkeys match, the CLI asks you to choose one by number and returns only
    that credential. The list includes account name, vault item, creation date and a short
    key ID. Type `n` to cancel; invalid input or closed stdin also denies the request.
    A single matching passkey proceeds automatically. The vault is checked again after
    a choice, so locking it or removing the selected key while the prompt is open denies
    the login. Bitwarden's master-password re-prompt
    setting is not separately enforced by virtbw.

Chromium browsers also send a special `.dummy` MakeCredential request to select a
CTAP 2.0 key by touch. virtbw recognizes that exact probe and asks **Select this
security key for the browser? (y/N)**. Type `y` to select it; the actual login
still asks for approval separately. The response uses a disposable credential
that is never stored. Real registrations remain disabled. This handles the
[browser's touch probe](https://github.com/chromium/chromium/blob/main/device/fido/make_credential_task.cc)
without enabling real registrations. With trusted-vault mode, selection is also prompt-free;
a probe requesting UV must pass the live vault check.

The CLI selects an account in the terminal. Library users can retain browser selection
by leaving `Options.SelectCredentialLocally` false. In that configuration, for verified
discoverable logins with multiple matches, the first assertion includes
`numberOfCredentials`; the browser retrieves the rest using
[`GetNextAssertion`](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetNextAssertion)
and shows
their account names. Each continuation uses the original site and challenge and re-reads
the live vault before signing. The sequence expires after 30 seconds of inactivity and
is invalidated by another CTAP command, a different HID channel, or USB reconnection.
Only credential IDs are held between requests. Identical credential IDs are deduplicated;
different credentials retain their original user handles. The browser controls how it
displays multiple keys for the same account. Requests containing an explicit credential
allow-list still return one matching assertion, as required by CTAP 2.0.

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

#### VirtualHere transport (experimental)

If the VirtualHere client and its driver are already installed, build and run:

```sh
go build -o ./target/virtbw ./cmd/virtbw
./target/virtbw --backend serve --serve-url http://localhost:8087 \
    --sync=false --transport virtualhere --listen 127.0.0.1:7575 \
    --trust-unlocked-vault start
```

The existing `bw serve` process must be unlocked. In VirtualHere's client, add
`127.0.0.1:7575` as a manual hub, then choose **Use this device** on
**virtbw Virtual FIDO**. The command above uses the unlocked vault as the login
authorization policy. Keep its terminal open: when multiple passkeys match, enter the
number of the one you want to use. No extra yes/no approval or PIN is requested.
Omit `--trust-unlocked-vault` to use terminal login approval instead; that default does not advertise UV. Closing terminal
input denies approval in the default mode. The `cli` Bitwarden
backend also works with `--transport virtualhere`. `--sync=false` uses the
vault as currently served; omit it to sync on startup.

Trial clients require TCP port 7575. A different port produces a server-license
error before USB attachment. If another server already uses IPv4 port 7575, use
`--listen '[::1]:7575'` and add `[::1]:7575` as the manual hub.

This path exports a software USB HID device directly over the recovered
VirtualHere protocol. It does not invoke virtbw's native HID creation code, so
virtbw itself does not need Apple's HID Virtual Device entitlement for this
transport. The installed VirtualHere client handles USB attachment.

This implementation supports one FIDO device and one owner, manual hub
connections, raw/LZ4 input framing, USB descriptors/control transfers, and
64-byte interrupt reports. It has no TLS, authentication, multicast discovery,
EasyFind, or remote administration. The CLI accepts only a loopback IP address.
The device uses virtbw's existing unallocated VID/PID `0000:0000`. This is an
interoperability experiment based on Linux server 4.8.8, not a general replacement
for the VirtualHere server.

Validation includes Linux HID enumeration through an independent VirtualHere to
USB/IP bridge, CTAPHID INIT, a fragmented 512-byte PING, GetInfo, and an automated
synthetic Bitwarden GetAssertion whose ECDSA signature is verified over TCP,
including multiple discoverable accounts with UV and GetNextAssertion in trusted-vault
mode, plus returning only the key chosen in the terminal. Tests verify signatures for distinct keys, channel isolation, expiry, and that
locking the vault or removing a passkey defeats a warm cache and pending continuation.
The unmodified Mac VirtualHere client successfully attaches the key on port 7575:
macOS exposes FIDO usage page `0xf1d0`, 64-byte reports, and completes INIT/GetInfo
through its HID API. The earlier server-license errors were caused by using port
7576. A complete browser login remains a manual validation step.

If you disconnect while a login approval is waiting, deny that old prompt before
reconnecting. The underlying backend has no cancellable approval API, so a new
binding waits for the previous backend request to return; late reports are
discarded. Native remains the default transport.

Transport and approval tests:

```sh
go test -race ./virtualhere ./cmd/virtbw ./bitwarden ./ctap ./ctap_hid ./u2f
```

The pre-existing `util.TestRequestBuffer` makes asynchronous assertions after its
test has returned and assumes ordering from a map; `go test -race ./...` can fail
there. The new transport uses its own FIFO and does not use that request buffer.

#### Native HID transport

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
