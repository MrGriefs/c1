[types/session]: https://github.com/MrGriefs/c1/blob/main/js_impl/src/types/Session.ts
[types/user]:    https://github.com/MrGriefs/c1/blob/main/js_impl/src/types/User.ts

# javascript implmentation

## requirements

- Node.js v12 or above
- `certbot` v2.7.1
- `openssl` v1.1.1j

## build

no build steps yet. currently in writing phase

## file system state

These are all files dropped by the server.  
From current working directory;

- `/data/sessions.json`  
  an index containing information about User Groups in the form of a [session data](#session-data) array.  
  only admins can cause this file to be mutated (and is therefore less vulnerable to attacks).
- <code>/data/sessions/{[session][types/session].uuid}/{[user][types/user].name}:{[user][types/user].auth}/{filename}</code>  
  a User Group - each user is given their own directory to upload files.  
  - Usernames are required to be unique in the specific User Group only.  
  - However, usernames are NOT unique from the admin User Group  
    (i.e. to upload in a User Group with the username of an admin, the admin's credentials must be used).
  - File names are hex encoded for simplicity and compatibility.
- `/data/sessions/00000000-0000-0000-0000-000000000000/...`  
  an internal User Group - used to store credentials of administrators. also may be used to share files between administrators.  
  this is the only User Group that usernames conflict with other User Groups.

## User Groups

A User Group is an isolated session where files can be uploaded and users created without consequence to other User Groups. They can also be given specific constraints (such as enforcing regular expression patterns for file names).  

In most common webservices, usernames are required to be unique identifiers at the root level. User Groups are an abstraction to leviate this constraint for convenience of users (in this case, students eagerly submitting exam files) and has the additional benefit of isolation and organisation preferable to this use case.  

## session data

See [`src/types/Session.ts`][types/session] for type definition.  
Session data is parsed from and stored as the following JSON:  

```jsonc
{
  // the unique identifier: used as the internal file path to group contents
  // and by the client to indicate what resource is being operated.
  "uuid": "31aa9163-3dc7-47ea-a453-adb154df4c2d",
  // display name: used by the client, mutable by an admin
  "name": "Group B - Task 1",
  // ISO-8601 date string of the resource creation date
  "created": "2023-10-13T14:52:39.497Z",
  // perpetrator's username that requested the server to create this resource
  "author": "admin27",
  // whether the session is closed and users can no longer "drop" files to this group
  "disabled": false,
}
```

## user data

See [`src/types/User.ts`][types/user] for type definition.  
User data is never stored formally, and is instead computed from reading directory file names.

Credentials are authenticated by checking whether the username already exists and the password hash match. If the username does not already exist, the user is created.

## External links

Resources that were used when researching problems encountered during this project.

1. Using Let's Encrypt CA for internal addresses (such as a LAN, as required by the Use Case)
   - <https://security.stackexchange.com/questions/121163/how-do-i-run-proper-https-on-an-internal-network>
   - (good read) <https://jsavoie.github.io/2021/06/01/letsencrypt.html>
1. Using certbot command-line interface
   - <https://eff-certbot.readthedocs.io/en/stable/using.html>
   - <https://letsencrypt.org/docs/challenge-types/#dns-01-challenge>
1. Filtering requests to private addresses
   - <https://datatracker.ietf.org/doc/html/rfc1918>
1. Node.js HTTPS and TLS documentation
   - <https://nodejs.org/api/https.html>
   - <https://nodejs.org/api/tls.html>
1. Using Node.js zlib and stream modules for compressing/decompressing payloads
   - <https://nodejs.org/api/zlib.html>
   - <https://nodejs.org/api/stream.html>
