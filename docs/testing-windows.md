# Testing jink on Windows

Step-by-step instructions for building jink on a Windows PC and checking that
it unblocks YouTube and Discord. The tools take about 20 minutes to install
once (mostly downloading); after that, each test takes a couple of minutes.

## 1. One-time setup

1. **Get the source onto the PC.** Copy the jink source zip (for example
   `jink-56884aa.zip`) to the PC: USB stick, Telegram, cloud drive.
2. **Unzip it to `C:\`.** Right-click the zip → **Extract All…**, change the
   destination to `C:\` → **Extract**. You should now have a folder
   `C:\jink` with `Cargo.toml` inside.
3. **Install Rust:**
   1. Go to <https://rustup.rs> and download `rustup-init.exe`. Run it.
   2. If it says the Visual Studio C++ build tools are missing, choose the
      option to **install them**. In the Visual Studio installer, keep the
      preselected "Desktop development with C++" and install.
   3. Back in the rustup window, press **Enter** for the default install.

   The first build downloads the exact Rust version jink pins on its own.
4. **Stop zapret**, so that two programs don't rewrite the same packets:
   - If zapret runs as a service: right-click its `service.bat` → **Run as
     administrator** → choose **Remove Services**.
   - Close any window running a `general…bat` / `winws.exe`.

## 2. Build jink

Open **cmd**: Start → type `cmd` → Enter. Then run these two commands,
replacing the path with your zapret-discord-youtube folder. To get the exact
path, Shift+right-click the folder in Explorer → **Copy as path**, and paste
it.

```bat
cd C:\jink
scripts\build-windows.cmd "C:\path\to\zapret-discord-youtube"
```

The first build takes a few minutes. It is done when you see
`Built target\release\jink.exe` and `Copied WinDivert64.sys`.

## 3. Run it

Open cmd **as Administrator**: Start → type `cmd` → right-click **Command
Prompt** → **Run as administrator**. Then:

```bat
cd C:\jink
target\release\jink.exe check "C:\path\to\zapret-discord-youtube\general (ALT).bat"
target\release\jink.exe run "C:\path\to\zapret-discord-youtube\general (ALT).bat"
```

`check` shows what jink will do with the strategy. `run` starts it: leave
that window open while you test.

1. Open YouTube and play a video. Does it start quickly? Is the quality
   sharp?
2. Open Discord and join a voice channel. Does voice connect?
3. Press **Ctrl+C** in the window. Does the internet still work normally
   afterwards?

Then repeat this step with `general (ALT13).bat`.

## 4. What to report

- The output of `check`.
- Everything jink printed while running, especially any line starting with
  `jink:`.
- What worked and what didn't in each test.
- If the build failed: the last 20 or so lines of the error.

When you are done, you can start zapret again as usual.
