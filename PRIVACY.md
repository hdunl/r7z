# Privacy

r7z does not collect, store or send any personal data. It has no accounts, no analytics,
no telemetry and no ads.

## What stays on your PC

- **Settings and recent archives** are saved in `%APPDATA%\r7z`.
- **Crash reports** are written to `%APPDATA%\r7z\crash.log` if the desktop app closes
  unexpectedly. They are never sent anywhere; you can attach one to a bug report yourself.
- **Undo** keeps backups of files replaced by an extraction in your temp folder, for the
  last five extractions.

The Microsoft Store version keeps these inside its own app storage, which Windows deletes
when you uninstall it. The GitHub version leaves `%APPDATA%\r7z` in place; delete that
folder to remove your settings.

## Network use

- **Microsoft Store version:** r7z makes no network connections. The Store handles
  updates.
- **Version downloaded from GitHub:** once a day the desktop app downloads a small,
  signed update manifest from `github.com/hdunl/r7z`, and downloads a new release when you
  choose to update. These are ordinary HTTPS requests to GitHub. They carry no identifier
  for you or your PC, and GitHub's own
  [privacy statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement)
  applies to them. Settings → Updates turns the check off.

Links such as "What's new" open in your web browser.

## Contact

Questions about privacy: open an issue at https://github.com/hdunl/r7z/issues.
