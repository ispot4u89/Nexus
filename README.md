# NEXUS Multi-Admin User Isolation

## Changes

- Regular administrators see and manage only users they created.
- The server enforces ownership on user update and delete requests; changing browser-side UI cannot bypass it.
- The super administrator sees a tab for their own users and a separate tab for each administrator's users.
- The super administrator can create users under the currently selected administrator tab and use all existing user-management actions on every administrator's users.
- Users from an older installation without an owner are assigned to the super administrator during migration.
- If an administrator is deleted, their users are reassigned to the super administrator instead of being orphaned.
- Imported-configuration ownership remains separate per administrator, and the Clear all action deletes only the signed-in administrator's imported configurations.

## Upgrade

1. Back up the existing application files and `data/nexus-data.json`.
2. Replace `index.js` with the one in this package.
3. Replace `public/index.html` with the one in this package.
4. Keep the existing `data/nexus-data.json`; do not delete it.
5. Restart the Node.js application.
6. Sign in as the super administrator and test the user tabs. Sign in as each regular administrator separately to verify they see only their own users.

This package contains application source only. It does not contain passwords, session data, or the live database. JavaScript syntax checks were run; this package has not been tested against your live server or database.


## Connection backend update

- Preserves the VLESS-over-WebSocket backend and `/ws` path from the supplied source.
- Sends the VLESS success response only after the destination TCP connection succeeds, avoiding a false-positive client connection when the target socket fails immediately.
- Logs destination and WebSocket stream errors to help diagnose connectivity.
- Keeps multi-administrator user ownership and server-side ownership checks.

Run `node --check index.js` before restarting. Back up `data/nexus-data.json` before replacing application files.
