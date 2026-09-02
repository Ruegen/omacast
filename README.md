# omacast

<p align="center">
  <img src="preview.png" alt="Omacast" />
</p>

Send a local video file to an AirPlay TV. No local player, no desktop mirror — the file plays on the TV.

Video only for now. Omacast does not change the TV volume (it never sets 100%).

## Install (Omarchy)

Needs ffmpeg. Omarchy / Hyprland.

```
cd ~/apps/omacast
cargo build --release
mkdir -p ~/.local/bin ~/.local/share/applications
cp target/release/omacast ~/.local/bin/omacast
cp packaging/Omacast.desktop ~/.local/share/applications/
```

```
source = ~/apps/omacast/packaging/hyprland-omacast.conf
```

Super+Space, Omacast. Pick the TV, PIN once, pick a file — it plays on the TV. Esc stops.

Headless: `omacast --play FILE --host IP`

No DoubleTake or omarchy-airplay dependency.

## Remove

```
rm -f ~/.local/bin/omacast ~/.local/share/applications/Omacast.desktop
```

Delete `~/apps/omacast` and `~/.config/omacast` for a full wipe. In Hyprland, remove the `source` line.

## Folders

`.mp4` `.mkv` `.mov`. Default is `~/Videos` if that folder exists.

Saved list: `~/.config/omacast/config.json`. On Files: `a` add a folder, `d` remove one. `--media-dir` adds a folder for this run only.

## Pairing

PIN is one-time. Enter on a TV pairs immediately if there are no saved keys (or pair-verify fails). After that, pick a file. Pairing keys live in `~/.config/omacast/` (not in git) — `credentials.json`, not the PIN.

You are asked again only if the TV forgets this client, or you delete that file. On the TV: **Settings → AirPlay → Allow Access = Anyone on the Same Network**.

## Hisense / AirPlay 2 screen TVs

The TV connects back to this machine. Allow inbound TCP and UDP **60000–60010** from the TV:

```
sudo ufw allow from <TV_IP> to any port 60000:60010 proto tcp
sudo ufw allow from <TV_IP> to any port 60000:60010 proto udp
```

## Keys

Every screen shows a keys panel.

**Discovery** `↑↓ select  Enter TV (pair)  r refresh  q quit`

**Files** `↑↓ select  type to search  Enter play  a add folder  d remove folder  Esc back`

**PIN** `0–9 enter code  Enter confirm  Esc cancel`

**Control** `Esc stop  q quit` — while sending to the TV. Receivers that take a URL still have Space play/pause, seek, and jump keys.

## Notes

- Local files only. No DRM. ffmpeg is required.
- `omacast --help` for `--play`, `--host`, `--media-dir`, and `--port`.

MIT, copyright Ruegen 2026.
