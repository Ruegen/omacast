-- Omacast: float on open, then the user can tile it (Omarchy Super+T).
--
-- float/center/size are static (apply once when the window maps). Do not pin:
-- a pinned window stays on every workspace and will not join the tiling layout.
--
-- From ~/.config/hypr/hyprland.lua:
--
--   dofile(os.getenv("HOME") .. "/apps/omacast/packaging/hyprland-omacast.lua")

o.window("omacast-app", { float = true, center = true, size = { 800, 500 } })
