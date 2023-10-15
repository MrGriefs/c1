/**
 * @fileoverview
 * this module is purposed for serving main API functions and handles anything related to the API's security, database and configuration.
 * 
 * note:
 * this is a HTTPS server only, requests to i.e. http://192.168.0.11/ will not be responded to.
 * if in the future, for whatever reason, a http -> https redirect is warranted,
 * the Strict-Transport-Security header is required to preserve HTTPS integrity.
 * 
 * see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import type http from 'node:http';
import https from 'node:https';
import { Buffer, btoa } from 'node:buffer';
import process from 'node:process';
import { setTimeout } from 'node:timers/promises';
import assert from 'node:assert';
import type * as Type from './types';
import { Fs, Net } from './Util.js';
import { randomUUID } from 'node:crypto';
import constants from 'node:constants';

// enforces all date strings to be in UTC time
process.env.TZ = 'UTC';

{ // save persistent config ever 1 hour to 1 hour 30 minutes
  function random_delay() {
    // a random interval between 0ms to 30 minutes
    // this will add some extra security as an attacker cannot easily predict when files are being written
    const interval = Math.ceil(Math.random() * 1_000 * 60 * 30);
    const hour = 1_000 * 60 * 60;

    return hour + interval;
  }

  function save_scheduler() {
    DropServer.Session.save();
    setTimeout(random_delay(), save_scheduler);
  }

  setTimeout(random_delay(), save_scheduler);
}

export namespace DropServer.Constants {
  export namespace Headers {
    export const XFilePath = 'x-file-path';
    // X-Session-ID header is NOT to be confused with a cookie session id -
    // it is the identifier for isolated DropServer user groups and must be used
    // by the client for the server to know *where* the file is being uploaded
    export const XSessionId = 'x-session-id';
  }
}

/**
 * this is what i like to call a "drop server".
 * it is a primitive file upload server where files can be "dropped" via a post request with credentials
 */
export namespace DropServer {
  export type Uid = string & { __TYPE__: Uid };
  export interface FileInfo {
    path: string;
    data: Buffer;
  }

  export type Context = {
    req: http.IncomingMessage;
    res: http.ServerResponse;
  };
  export namespace Context {
    export type Auth = { user: Type.User; };
    export type SessionId = { session_id: Type.Session.Uuid; };
    export type FilePath = { file_path: string; };
  }

  export const store = path.join(process.cwd(), 'data');

  export namespace FileStore {
    export async function getUserDataFromState(store: string) {
      const data: { [username: string]: string } = {};

      for (const dir of await fs.readdir(store, { withFileTypes: true })) {
        if (!dir.isDirectory()) continue;

        const subdirs = await fs.readdir(path.join(store, dir.name));
        if (subdirs.length !== 1)
          throw Error(
            'filestore is in an unexpected state: ' +
            `${dir.name} contains ${subdirs.length} entities, expected 1`
          );

        const auth_cred = subdirs[0];
        data[dir.name] = auth_cred;
      }


      return data;
    }
  }
}

export namespace DropServer.Admin {
  export function add({ name, auth }: Type.User) {
    DropServer.Session.system.users.set(name, auth);
  }

  export function remove(username: string) {
    DropServer.Session.system.users.delete(username);
  }

  export function is({ name, auth }: Type.User) {
    // offensive programming (if credentials were undefined, this function would
    // return true if the username doesn't exist - opening an exploit)
    assert(auth !== undefined);
    return DropServer.Session.system.users.get(name) === auth;
  }
}

export namespace DropServer.Session {
  export const SESSION_OLD_AFTER_DURATION = 24 * 60 * 60 * 1_000;

  const sessions = new Map<Type.Session['uuid'], Type.Session>();
  const location = path.join(store, 'sessions.json');

  namespace _ {
    // ensure file system state
    await fs.mkdir(path.join(store, 'sessions_backups')).catch(Fs.ignore_eexist);

    const raw_sessions: Type.Session[] = JSON.parse(await fs.readFile(location, 'utf8'));

    const promises: Promise<any>[] = [];
    const min_date = new Date().valueOf() - SESSION_OLD_AFTER_DURATION;
    for (const raw of raw_sessions) {
      assert(!sessions.has(raw.uuid)); // offensive programming

      // instead of creating a new object, we reuse the object created by the JSON parser
      raw.created = new Date(raw.created);
      raw.disabled ||= raw.created.valueOf() > min_date;

      // pre-cache users of active User Groups
      if (raw.disabled === false) {
        raw.users = new Map() as Type.Session['users'];

        promises.push(
          (async () => {
            for await (const [uid, cred] of read_users(raw.uuid))
              raw.users.set(uid, cred);
          })(),
        );
      }

      sessions.set(raw.uuid, raw);
    }

    await Promise.all(promises);
  }
    
  // ensure system group. the system group is used to store admin users
  const system_uuid = '00000000-0000-0000-0000-000000000000' as Type.Session['uuid'];
  if (!DropServer.Session.exists(system_uuid))
    await DropServer.Session.create({
      uuid: system_uuid,
      author: 'system',
      name: 'System',
    });

  export const system: Type.Session = DropServer.Session.get(system_uuid);

  export async function* read_users(session_id: Type.Session.Uuid) {
    const ents = await fs.readdir(path.join(store, session_id), { withFileTypes: true });

    for (const ent of ents) {
      const parts = ent.name.split(':');
      assert(parts.length == 2);

      yield parts;
    }
  }

  export async function create({ uuid, author, name }: Pick<Type.Session, 'uuid' | 'author' | 'name'>): Promise<void> {
    await fs.mkdir(path.join(store, uuid));

    sessions.set(uuid, {
      uuid,
      name,
      author,
      created: new Date(),
      disabled: false,
      users: new Map() as Type.Session['users'],
    });
  }

  export function get(id: Type.Session.Uuid): Readonly<Type.Session> | undefined {
    return sessions.get(id);
  }

  export function update(session: Readonly<Type.Session>): Type.Session {
    return session; // noop
  }

  export async function is_disabled(session: Type.Session) {
    if (session.disabled === true)
      return true;

    if (session.created.valueOf() - new Date().valueOf() > SESSION_OLD_AFTER_DURATION)
      return session.disabled = true;

    return false;
  }

  export async function exists(id: Type.Session.Uuid) {
    return sessions.has(id);
  }

  export async function save() {
    await fs.rename(location, path.join(store, 'sessions_backups', `sessions_${new Date().toISOString()}.json`));
    await fs.writeFile(location, JSON.stringify(sessions.values()), 'utf8');
  }
}

export namespace DropServer {
  const api_map = {
    '/files': {
      'POST': Tasks.Upload.POST,
    },
    '/session': {
      'POST': Tasks.Session.POST,
    },
  } as const;

  // 2x faster than 'await'ing individually/sequentially (see perf/readfile-concurrency)
  const stack = await Promise.all([
    fs.readFile('./.ssl/ca.pem'),
    fs.readFile('./.ssl/dh1.pem'),
    fs.readFile('./.ssl/cert.pem'),
    fs.readFile('./.ssl/key.pem'),
  ]);

  export const server = https.createServer({
    // see https://nodejs.org/api/tls.html#tlscreatesecurecontextoptions
    key: stack.pop(),
    cert: stack.pop(),
    dhparam: stack.pop(),
    // do not trust well-known CAs, only trust our CAs as chainable.
    // this will reject peers with any CA that is not ours
    ca: stack.pop(),

    secureOptions: 0
      | constants.SSL_OP_NO_SSLv2
      | constants.SSL_OP_NO_SSLv3,
    requestCert: true,
    rejectUnauthorized: true,
  }, (req, res) => {
    // if a proxy/load balancer is used, ensure the load balancer's client is https too
    const proxy_protocol = req.headers['x-forwarded-proto'];
    if (proxy_protocol && proxy_protocol !== 'https')
      return void res
        .writeHead(301, { Location: `https://${req.headers.host}${req.url!}` })
        .end();

    const nested = api_map[req.url];
    if (nested === undefined)
      return void res
        .writeHead(404)
        .end();

    const method = nested[req.method];
    if (method === undefined)
      return void res
        .writeHead(405)
        .end();
    
    const addr_info = req.socket.address();
    if (!('address' in addr_info))
      // .address() may return an empty object if socket is destroyed
      return void res
        .writeHead(500)
        .end();
    
    // for security, only accept LAN connections for now. SSL/cert is a todo
    if (Net.get_address_type(addr_info) !== Net.AddressType.Private)
      return void res
        .writeHead(403)
        .end();

    // promise creation is an exhaustive process. but, handing the main api function call to
    // the scheduler allows the api to remain non-busy, serving multiple requests concurrently
    new Promise(resolve => resolve(method(req, res)))
      .catch(err => {
        if (err === undefined) return; // api short-circuit
        console.error(`${req.method} ${req.url}: ${err}`);

        if (res.closed !== true)
          res
            .writeHead(500)
            .end();
      });
  })

  server.listen(8443);
}

export namespace DropServer.Tasks {
  function assertFilePath(ctx: Context): asserts ctx is Context & Context.FilePath {
    const { req, res } = ctx;
    const path = req.headers[DropServer.Constants.Headers.XFilePath];

    if (
      // headers may contain non-string values in certain cases, as per nodejs http docs
      typeof path !== 'string' ||
      path.length === 0 ||
      path.length > 64
    )
      throw void res
        .writeHead(400)
        .end();

    (ctx as Context & Context.FilePath).file_path = path;
  }

  function assertSessionId(ctx: Context): asserts ctx is Context & Context.SessionId {
    const { req, res } = ctx;
    const session = req.headers[DropServer.Constants.Headers.XSessionId];

    if (typeof session !== 'string')
      throw void res
        .writeHead(400)
        .end();

    (ctx as Context & Context.SessionId).session_id = session as Type.Session.Uuid;
  }

  /** this asserts the existence of authorisation, it does NOT assert authentication validity */
  function assertAuth(ctx: Context): asserts ctx is Context & Context.Auth {
    const { req, res } = ctx;
    const auth = req.headers['authorization'];

    if (typeof auth !== 'string' || !auth.startsWith('Basic '))
      throw void res
        .writeHead(401)
        .end();

    const b64_part = auth.substring('Basic '.length);
    const text = btoa(b64_part);

    const terminator_index = text.indexOf(':');

    if (terminator_index === -1)
      throw void res
        .writeHead(400)
        .end();

    const username = text.substring(0, terminator_index);
    const password = text.substring(1 + terminator_index);

    if (username.length === 0 || password.length === 0)
      throw void res
        .writeHead(400)
        .end();

    (ctx as Context & Context.Auth).user = { name: username, auth: password };
  }

  function assertAuthIsAdmin({ res, user }: Context & Context.Auth) {
    if (Admin.is(user) !== true)
      throw void res
        .writeHead(403)
        .end();
  }

  export namespace Upload {
    export function POST(ctx: Context) {
      assertAuth(ctx);
      assertSessionId(ctx);
      assertFilePath(ctx);

      const { req, res, user, session_id, file_path } = ctx;

      const session = DropServer.Session.get(session_id);
      if (session === undefined || session.disabled !== false)
        return void res
          .writeHead(404)
          .end('{"message":"Session does not exist or is disabled"}');

      let body = '';
      req
        .on('data', data => void (body += data))
        .once('end', () => {

        });
    }

    export function GET(req: http.IncomingMessage, res: http.ServerResponse) {
      const path = assertFilePath(req, res);
      const auth = assertAuth(req, res);


    }
  }

  export namespace Session {
    const queue = Promise.resolve();
    export async function POST(ctx: Context) {
      assertAuth(ctx);
      assertAuthIsAdmin(ctx);
      assertSessionId(ctx);

      const { req, res, session_id, user: auth } = ctx;

      // io cannot be asynchronous. this queue prevents race conditoons caused by asynchronous execution
      queue
        .then(async () => {
          if (DropServer.Session.exists(session_id))
            return void res
              .writeHead(400)
              .end('{"message":"Cannot create session with same session id"}');

          await DropServer.Session.create(session_id, auth.name);

          res
            .writeHead(204)
            .end();
        })
        .catch(e => { throw e });
    }

    export namespace Patch {
      export type Schema = {
        disabled: boolean;
      };
      export namespace Schema {
        export const map = {
          'disabled': true,
        };
        export const length = Object.keys(map).length;
      }
    }

    export async function PATCH(ctx: Context) {
      assertAuth(ctx);
      assertAuthIsAdmin(ctx);
      assertSessionId(ctx);

      const { req, res, user: auth, session_id } = ctx;

      // io cannot be asynchronous. this queue prevents race conditoons where the directory is deleted after checking it exists
      queue
        .then(async () => {
          const session = DropServer.Session.get(session_id);
          if (session === undefined)
            return void res
              .writeHead(400) // 404? resource was found, but not object
              .end('{"message":"Session does not exist"}');
          
          let body = '';
          req
            .on('data', data => void (body += data))
            .once('end', () => {
              let json: Patch.Schema;
              
              try {
                json = JSON.parse(body)
              } catch {
                return void res
                  .writeHead(400)
                  .end();
              }

              const keys = Object.keys(json) as (keyof typeof json)[];
              // (defensive programming) ensure json does not have more than the expected amount of keys before iterating
              if (keys.length > Patch.Schema.length)
                return void res
                  .writeHead(400)
                  .end();
              
              // validate
              for (const key of keys) {
                if (key in Patch.Schema.map) continue;

                return void res
                  .writeHead(400)
                  .end();
              }

              // evaluate
              for (const key of keys) {
                const val = json[key];
                switch (key) {
                  case 'disabled':
                    session.disabled = val;
                    break;

                  default: throw Error('offensive programming');
                }
              }

              res
                .writeHead(200, JSON.stringify(session))
                .end();
            });
        })
        .catch(e => { throw e });
    }

    // todo: DELETE method
  }
}
