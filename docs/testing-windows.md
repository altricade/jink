# Testing jink on Windows

Step-by-step instructions for checking, on a Windows PC, that the jink
service unblocks YouTube and Discord. Nothing needs to be installed or
built: GitHub builds jink on every change, and you download the result.
Each test takes a few minutes.

## 1. Get jink

1. On GitHub, open the jink repository → **Actions** → **windows** → the
   newest run with a green check.
2. At the bottom of the run's page, under **Artifacts**, click
   **jink-windows** to download a zip.
3. Unzip it to `C:\jink`: right-click the zip → **Extract All…**, type
   `C:\jink` as the destination → **Extract**. The folder now has
   `jink.exe` and `WinDivert64.sys` (and two license files).
4. **Stop zapret**, so that two programs don't rewrite the same packets:
   - If zapret runs as a service: right-click its `service.bat` → **Run as
     administrator** → choose **Remove Services**.
   - Close any window running a `general…bat` / `winws.exe`.

## 2. Install the service

Open cmd **as Administrator**: Start → type `cmd` → right-click **Command
Prompt** → **Run as administrator**. Then:

```bat
cd C:\jink
jink service install
jink service status
```

`status` should say `running`. The service now starts with Windows; it
stays off until you turn it on.

## 3. Test it

These commands work in any cmd window (no Administrator needed from now
on), from `C:\jink`:

```bat
jink ctl start alt
jink ctl status
```

`status` should show `"state": "active"` after a moment.

1. Open YouTube and play a video. Does it start quickly? Is the quality
   sharp?
2. Open Discord and join a voice channel. Does voice connect?
3. Try another strategy: `jink ctl start alt13`, and test again.
   `jink ctl strategies` lists all of them.
4. Let jink find the best one: `jink ctl find`, then run `jink ctl status`
   every 30 seconds or so. It takes about two minutes; when it is done,
   `found` shows the result and jink is on with the strategy it kept.
5. `jink ctl stop`. Does the internet still work normally?
6. Restart Windows, then `jink ctl status`: the service is running (off).
   `jink ctl boot on` makes it turn on by itself at startup; try that and
   restart again.

## 4. What to report

- What worked and what didn't in each test.
- The output of the `jink ctl status` that looked wrong, if any.
- The log: `C:\ProgramData\jink\jink.log` (open it with Notepad).

## 5. Remove it

```bat
cd C:\jink
jink service uninstall
```

(in cmd as Administrator). This removes the service and its settings and
log. Then you can start zapret again as usual.
