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
import fs_sync from 'node:fs';
import path from 'node:path';
import type http from 'node:http';
import https from 'node:https';
import { Buffer, btoa } from 'node:buffer';
import process from 'node:process';
import { setTimeout } from 'node:timers/promises';
import assert from 'node:assert';
import type * as Type from './types';
import { Fs, Net, exhaust_match, type Only } from './Util.js';
import { randomUUID } from 'node:crypto';
import constants from 'node:constants';
import zlib from 'node:zlib';
import { pipeline } from 'node:stream/promises';

// enforces all date strings to be in UTC time
process.env.TZ = 'UTC';

await DropServer.Session.load_state();

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
    export type Session = { session: Readonly<Type.Session.Enabled>; };
    export type FilePath = { computed_file_path: string; };
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

export namespace DropServer.Session {
  export const SESSION_OLD_AFTER_DURATION = 24 * 60 * 60 * 1_000;

  const sessions = new Map<Type.Session['uuid'], Type.Session>();
  const location = path.join(store, 'sessions.json');

  export let system: Type.Session.Enabled | null = null;

  export async function load_state() {
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
        raw.users = new Map();

        promises.push(
          read_users(raw.uuid).then(users => {
            for (const [uid, cred] of users)
              (raw.users as Map<string, string>).set(uid, cred);
          }),
        );
      }

      sessions.set(raw.uuid, raw);
    }

    await Promise.all(promises);

    // ensure system group. the system group is used to store admin users
    const system_uuid = '00000000-0000-0000-0000-000000000000' as Type.Session['uuid'];
    if (true !== DropServer.Session.exists(system_uuid))
      // anything other than true? create or throw
      await _create({
        uuid: system_uuid,
        author: 'system',
        name: 'System',
      });

    system = DropServer.Session.get(system_uuid) as Type.Session.Enabled;
  }

  namespace ReadUsers {
    export function* create_generator(ents: fs_sync.Dirent[]) {
      for (const ent of ents) {
        const parts = ent.name.split(':');
        assert(parts.length === 2);
        
        yield parts;
      }
    }
  }

  // async generator creates a promise at every yield. we don't want O(n) overhead from the promise api
  // use a (non-async generator) resolver instead:
  export function read_users(session_id: Type.Session.Uuid) {
    return fs.readdir(path.join(store, session_id), { withFileTypes: true })
      .then(ReadUsers.create_generator);
  }

  async function _create(
    options:
      & Required<Pick<Type.Session, 'uuid' | 'author' | 'name'>>
      & Partial<Pick<Type.Session, 'disabled'>>
  ): Promise<void> {
    let session = options as Type.Session;
    await fs.mkdir(path.join(store, session.uuid));
    
    session.disabled ??= false;
    session.created = new Date();

    if (false === session.disabled)
      session.users = new Map() as Type.Session.Enabled['users'];

    sessions.set(session.uuid, session);
  }

  // "safety" wrapper around the internal create function
  export async function create(options: Omit<Parameters<typeof _create>[0], 'uuid'>): Promise<Type.Session['uuid']> {
    let session = options as Type.Session;

    do session.uuid = randomUUID() as Type.Session['uuid'];
    while (exists(session.uuid));

    await _create(session);

    return session.uuid;
  }

  export function get(id: Type.Session.Uuid): Readonly<Type.Session> | undefined {
    return sessions.get(id);
  }

  // type cast for more verbose mutation
  export function mutate(session: Readonly<Type.Session>): Type.Session {
    return session; // noop
  }

  export function is_disabled(session: Type.Session): true | false {
    if (session.disabled === true)
      return true;
    
    if (session === system)
      // system group users must not be un-cached
      return false;

    if (session.created.valueOf() - new Date().valueOf() > SESSION_OLD_AFTER_DURATION) {
      // free the user map from memory. we don't need them anymore
      delete session.users;
      // hack: session is Type.Session.Enabled, so it won't allow assigning
      // disabled to anything other than false.
      return session.disabled = true as false;
    }

    return false;
  }

  export function exists(id: Type.Session.Uuid) {
    return sessions.has(id);
  }

  export async function save() {
    await fs.rename(location, path.join(store, 'sessions_backups', `sessions_${new Date().toISOString()}.json`));
    await fs.writeFile(location, JSON.stringify(sessions.values()), 'utf8');
  }
}

export namespace DropServer.Session.User {
  type WritableMap = Map<string, string>;
  export function add(session: Type.Session.Enabled, { name, auth }: Type.User) {
    // offensive programming: don't trust all uses of this function to be sequential/synchronous
    assert(!session.users.has(name));
    (session.users as WritableMap).set(name, auth);
  }

  export function remove(session: Type.Session.Enabled, { name, auth }: Type.User) {
    const auth2 = session.users.get(name);
    assert(auth2 !== undefined && auth2 === auth);
    (session.users as WritableMap).delete(name);
  }

  /** remove a user without the user's credentials, i.e. an admin removing a user on their behalf */
  export function unsafe_remove(session: Type.Session.Enabled, { name }: Only<Type.User, 'name'>) {
    assert(session.users.has(name));
    (session.users as WritableMap).delete(name);
  }

  export function is(session: Type.Session.Enabled, { name, auth }: Type.User): true | false {
    switch (session.users.get(name)) {
      // offensive programming (if credentials were undefined, this function would
      // return true if the username doesn't exist - opening an exploit)
      case undefined: throw Error('user does not exist (raced?)');
      case auth: return true;
      default: return false;
    }
  }

  export enum Qualify {
    /** user does not exist */
    NO_USER,
    /** user exists, credentials match */
    IS_USER,
    /** user exists, credentials do not match */
    BAD_AUTH,
  }  

  /** returns the enum for authentication the user has (authenticity qualification) */
  export function qualify(session: Type.Session.Enabled, { name, auth }: Type.User): Qualify {
    assert(auth !== undefined);
    const auth2 = session.users.get(name);
    
    switch (auth2) {
      case undefined:
        return Qualify.NO_USER;
      case auth:
        return Qualify.IS_USER;
      default:
        return Qualify.BAD_AUTH;
    }
  }
}

export namespace DropServer.Session.User.File {
  export function relative_path(session: Type.Session, { name, auth }: Type.User, file_path: string) {
    return path.join(session.uuid, `${name}:${auth}`, file_path);
  }

  export function full_path(session: Type.Session, { name, auth }: Type.User, file_path: string) {
    return path.join(DropServer.store, session.uuid, `${name}:${auth}`, file_path);
  }

  export function relative_to_full_path(relative: string) {
    return path.join(DropServer.store, relative);
  }
}

export namespace DropServer.Admin {
  // shortcut functions

  export function add(user: Type.User) {
    DropServer.Session.User.add(DropServer.Session.system, user);
  }

  export function remove(user: Type.User) {
    DropServer.Session.User.remove(DropServer.Session.system, user);
  }

  export function is(user: Type.User) {
    return DropServer.Session.User.is(DropServer.Session.system, user);
  }
}

// 2x faster than 'await'ing individually/sequentially (see perf/readfile-concurrency)
const _DropServer_stack = await Promise.all([
  fs.readFile('./.ssl/ca.pem'),
  fs.readFile('./.ssl/dh1.pem'),
  fs.readFile('./.ssl/cert.pem'),
  fs.readFile('./.ssl/key.pem'),
]);

export namespace DropServer {
  // see https://github.com/microsoft/TypeScript/issues/53715
  const stack = _DropServer_stack;
  const api_map = {
    '/file': {
      POST: HttpMethods.File.POST,
    },
    '/session': {
      POST: HttpMethods.Session.POST,
      PATCH: HttpMethods.Session.PATCH,
    },
  } as const;

  export const server = https.createServer({
    // see https://nodejs.org/api/tls.html#tlscreatesecurecontextoptions
    key: stack.pop(),
    cert: stack.pop(),
    dhparam: stack.pop(),
    // do not trust well-known CAs, only trust our CAs as chainable.
    // this will reject peers with any CA that is not ours
    ca: stack.pop(),

    requestTimeout: 1_000 * 60 * 8,

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

        if (res.closed !== true && res.destroyed !== true)
          res
            .writeHead(500)
            .end();
      });
  })

  server.listen(8443);
}

export namespace DropServer.HttpMethods {
  import User = DropServer.Session.User;

  function assertFilePath(ctx: Context): asserts ctx is Context & Context.FilePath {
    const { req, res } = ctx;
    let path = req.headers[DropServer.Constants.Headers.XFilePath];

    if (
      // headers may contain non-string values in certain cases, as per nodejs http docs
      typeof path !== 'string' || (
        path = path.normalize('NFC'),
        path.length === 0 ||
        path.length > 64
      ) || (
        path = Buffer.from(path, 'utf8').toString('hex'),
        path.length > 128
      )
    )
      throw void res
        .writeHead(400)
        .end();

    (ctx as Context & Context.FilePath).computed_file_path = path;
  }

  function assertSessionId(ctx: Context): Type.Session.Uuid {
    const { req, res } = ctx;
    const session = req.headers[DropServer.Constants.Headers.XSessionId];

    if (typeof session !== 'string')
      throw void res
        .writeHead(400)
        .end();

    return session as Type.Session.Uuid;
  }

  function assertSession(ctx: Context): asserts ctx is Context & Context.Session {
    const { res } = ctx;
    
    const uuid = assertSessionId(ctx);
    const session = DropServer.Session.get(uuid);

    if (session === undefined || DropServer.Session.is_disabled(session))
      return void res
        .writeHead(404)
        .end('{"message":"Session does not exist or is disabled"}');

    (ctx as Context & Context.Session).session = session as Type.Session.Enabled;
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

  function assertAuthIsSessionUser({ res, user, session }: Context & Context.Auth & Context.Session) {
    const _ = User.qualify(session, user);
    switch (_) {
      // force typescript to error if this match doesn't include all enum cases
      default: throw exhaust_match(_);

      case User.Qualify.BAD_AUTH:
        throw void res
          .writeHead(401)
          .end();

      case User.Qualify.NO_USER:
        // create the user
        User.add(session, user);
        break;

      case User.Qualify.IS_USER:
        break; // continue
    }
  }
  
  function assertJson<T extends object>({ res }: Context, body: string): T {
    try {
      return JSON.parse(body);
    } catch {
      return void res
        .writeHead(400)
        .end();
    }
  }

  function assertValidSchema({ res }: Context, map: object, keys: string[], length: number): void {
    // (defensive programming) ensure json does not have more than the expected amount of keys before iterating
    if (keys.length > length)
      return void res
        .writeHead(400)
        .end();
    
    // validate
    for (const key of keys) {
      if (key in map && typeof key === map[key]) continue;

      return void res
        .writeHead(400)
        .end();
    }
  }

  export namespace Mutex {
    // a forethought mutex implementation
    const table = new Set<string>(); // string reference table

    export function lock(str: string): boolean {
      const has = table.has(str);
      // if the scheduler is able to pause execution here, and run something else,
      // then this is flawed. but im almost certain that only occurs in between
      // (async) function calls, which is accounted for correctly
      table.add(str);
      return has;
    }

    export function unlock(str: string): void {
      table.delete(str);
    }
  }

  export namespace File {
    // students can upload files 1 GiB or less (anything more than 1 Gibibyte would likely
    // take too long to send)
    const CONTENT_LENGTH = 1_024 ** 3;

    export function POST(ctx: Context) {
      assertAuth(ctx);
      assertFilePath(ctx);
      assertSession(ctx);
      assertAuthIsSessionUser(ctx);

      const { req, res, user, session, computed_file_path } = ctx;
      const rel_path = DropServer.Session.User.File.relative_path(session, user, computed_file_path);

      // this function is executed in the asynchronous
      // scheduler context, therefore a mutex is needed
      if (Mutex.lock(rel_path))
        return res.writeHead(409).end();

      try {
        const h_content_length = req.headers['content-length'];
        if (
          typeof h_content_length !== 'string' ||
          +h_content_length > CONTENT_LENGTH
        )
          return void res.writeHead(411).end();

        const file_path = DropServer.Session.User.File.relative_to_full_path(rel_path);

        // support for multiple compression algorithms
        // todo: currently this implementation will keep reading
        // data even after the 1 GiB limit
        switch (req.headers['content-encoding']) {
          case undefined:
          case '': {
            req.pipe(fs_sync.createWriteStream(file_path));
            break;
          }
          case 'br':
            pipeline(req, zlib.createBrotliDecompress(), fs_sync.createWriteStream(file_path))
              // pipeline() is an async function, and thus is being scheduled outside of this function
              // (the global scope). we don't want error to escape to the global scope
              .catch(console.error);
            break;
          case 'gzip':
            pipeline(req, zlib.createGunzip(), fs_sync.createWriteStream(file_path))
              .catch(console.error);
            break;
          case 'deflate':
            pipeline(req, zlib.createInflate(), fs_sync.createWriteStream(file_path))
              .catch(console.error);
            break;
          default:
            return void res.writeHead(400).end();
        }

        req.once('end', () => void res.writeHead(204).end());
      } finally {
        Mutex.unlock(rel_path);
      }
    }

    export function GET(ctx: Context) {
      assertAuth(ctx);
      assertFilePath(ctx);
      assertSession(ctx);
      assertAuthIsSessionUser(ctx);

      const { req, res, user, session, computed_file_path } = ctx;
      const rel_path = DropServer.Session.User.File.relative_path(session, user, computed_file_path);

      // mark file as busy
      if (Mutex.lock(rel_path))
        return res.writeHead(409).end();
      
      try {
        const file_path = DropServer.Session.User.File.relative_to_full_path(rel_path);
        if (true !== fs_sync.existsSync(file_path))
          return res.writeHead(404).end();

        // this is not a compliant accept-encoding parser
        // see https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.3
        switch (req.headers['accept-encoding']) {
          case undefined:
          case '': {
            res.writeHead(200);
            fs_sync.createReadStream(file_path).pipe(res);
            break;
          }
          case 'br':
            res.writeHead(200, { 'Content-Encoding': 'br' });
            pipeline(fs_sync.createReadStream(file_path), zlib.createBrotliCompress(), res)
              .catch(console.error);
            break;
          case 'gzip':
            res.writeHead(200, { 'Content-Encoding': 'gzip' });
            pipeline(fs_sync.createReadStream(file_path), zlib.createGzip(), res)
              .catch(console.error);
            break;
          case 'deflate':
            res.writeHead(200, { 'Content-Encoding': 'deflate' });
            pipeline(fs_sync.createReadStream(file_path), zlib.createDeflate(), res)
              .catch(console.error);
            break;
          default:
            return void res.writeHead(400).end();
        }
      } finally {
        Mutex.unlock(rel_path);
      }
    }
  }

  export namespace Session {
    type Schema = {
      disabled: boolean;
      name: string;
    };
    namespace Schema {
      export const map = {
        'disabled': 'boolean',
        'name': 'string',
      } as const;
      export const length = Object.keys(map).length;

      export function assertSanitised({ res }: Context, json: Schema, keys: (keyof typeof Schema.map)[]) {
        for (const key of keys) {
          switch (key) {
            case 'name': {
              let v = json[key];
              if (v.length > 32)
                return void res
                  .writeHead(400)
                  .end('{"message":"\'name\' must not exceed 32 characters"}');

              v = v.normalize('NFC'); // decrease string length by normaling chars
              let rebuilt = '';
              for (let i = 0; i != v.length; ++i) {
                if (v.charCodeAt(i) < 20) continue;
                rebuilt = rebuilt + v[i];
              }

              if (rebuilt.length === 0)
                return void res
                  .writeHead(400)
                  .end('{"message":"\'name\' must be at least 1 character in length"}');
            }
          }
        }
      }
    }

    export function POST(ctx: Context) {
      assertAuth(ctx);
      assertAuthIsAdmin(ctx);

      const { req, res, user } = ctx;

      let body = '';
      req
        .setEncoding('utf8')
        .on('data', data => void (body += data))
        .once('end', () => {
          const json = assertJson<Schema>(ctx, body);
          const keys = Object.keys(json) as (keyof typeof json)[];
          assertValidSchema(ctx, Schema.map, keys, Schema.length);
          Schema.assertSanitised(ctx, json, keys);

          const options: Parameters<typeof DropServer.Session.create>[0] = {
            author: user.name,
            name: 'Unnamed',
          };

          // evaluate
          for (const key of keys) {
            assert(key in Schema.map); // offensive programming
            /* @ts-expect-error */
            options[key] = json[key];
          }
          
          const session_id = DropServer.Session.create(options);

          res
            .writeHead(200)
            .end(`{"session_id":"${session_id}"}`);
        });
    }

    export function PATCH(ctx: Context) {
      assertAuth(ctx);
      assertAuthIsAdmin(ctx); // is admin, don't need to authenticate
      assertSession(ctx);

      const { req, res, session } = ctx;
      
      if (true !== DropServer.Session.exists(session.uuid))
        return void res.writeHead(404).end();

      let body = '';
      req
        .setEncoding('utf8')
        .on('data', data => void (body += data))
        .once('end', () => {
          const json = assertJson<Schema>(ctx, body);
          const keys = Object.keys(json) as (keyof typeof json)[];
          assertValidSchema(ctx, Schema.map, keys, Schema.length);
          Schema.assertSanitised(ctx, json, keys);

          if (true !== DropServer.Session.exists(session.uuid))
            return void res.writeHead(404).end();

          // evaluate
          const mut_session = DropServer.Session.mutate(session);
          for (const key of keys) {
            assert(key in Schema.map); // offensive programming
            /* @ts-expect-error */
            mut_session[key] = json[key];
          }

          res
            .writeHead(200, JSON.stringify(session))
            .end();
        })
    }

    // todo: DELETE method
  }
}
