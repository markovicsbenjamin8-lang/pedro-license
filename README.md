# Pedro Debug — License Server

A local Node.js server + HTML dashboard that gates access to the Pedro Debug Meteor addon by Minecraft username.

---

## How it works

1. The **license server** runs on your machine at `http://localhost:3000`.
2. When Minecraft loads the addon, `PedroDebug.java` makes a `GET /check?username=<mc_name>` request.
3. If the username has a valid, non-blacklisted, non-expired key → the addon loads normally.
4. If not → the game crashes immediately with a clear error message in the log.

---

## Setup (first time)

### Requirements
- [Node.js](https://nodejs.org) v18 or newer

### Install dependencies
```
cd "Pedro Debug/license-server"
npm install
```

### Start the server
```
node server.js
```

The server starts at **http://localhost:3000**.  
Open that URL in your browser to access the admin dashboard.

> Keep the server running whenever you want the addon to work.  
> If the server is offline, the addon will crash the game.

---

## Dashboard guide

### Generate a key
1. Enter one or more Minecraft usernames (comma separated).
2. Pick an expiry: **Lifetime** (never expires), a specific **date**, or a number of **days from now**.
3. Click **Generate Key** — a random key like `A3FX-9QWP-ZK12-LMRB` is created and shown in the table.

### Blacklist a key
Click the red **Blacklist** button next to any key. The player will be kicked from the addon on their next login. Click **Unblacklist** to reinstate it instantly.

### Edit a key (change users or expiry)
Click **Edit** on any row. You can:
- Replace or add usernames
- Change the expiry type/date

### Delete a key
Click **Delete** to permanently remove it.

### Search & filter
Use the search box to find a key by key value or username.  
Use the status dropdown to show only Active / Blacklisted / Expired keys.

---

## API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/check?username=X` | Check if a username has a valid key (used by the Java client) |
| GET | `/admin/keys` | List all keys |
| POST | `/admin/add-key` | Create a new key `{ users[], expiry }` |
| POST | `/admin/blacklist/:id` | Blacklist/unblacklist a key `{ blacklisted: true\|false }` |
| PUT | `/admin/key/:id/users` | Change users on a key `{ users[] }` |
| PUT | `/admin/key/:id/expiry` | Change expiry on a key `{ expiry: timestamp\|null }` |
| DELETE | `/admin/key/:id` | Delete a key |

---

## File structure

```
license-server/
  server.js      ← Express API server
  index.html     ← Admin dashboard (served at localhost:3000)
  db.json        ← Key database (plain JSON, auto-updated)
  package.json   ← Node dependencies
```

---

## Changing the server port

Edit the `PORT` constant at the top of `server.js`, and update `LICENSE_SERVER` in `PedroDebug.java` to match.
