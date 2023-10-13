import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { Buffer, btoa } from 'node:buffer';
import process from 'node:process';
import { Fs } from './Util';
import { setTimeout } from 'node:timers/promises';
import assert from 'node:assert';

await DropServer.Session.init();

// ensure system group. the system group is used to store admin users
{
  const system_id = 'system' as DropServer.Session.Id;
  if (!DropServer.Session.exists(system_id)) {
    await DropServer.Session.create(system_id, 'system');
  }

  DropServer.Session.system = DropServer.Session.get(system_id);
}

// save persistent config ever 1 hour to 1 hour 30 minutes
{
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
    // it is the identifier for isolated DropServer file groups and must be used
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
    export type Auth = { auth: { username: string, password: string } };
    export type SessionId = { session_id: DropServer.Session.Id };
    export type FilePath = { file_path: string };
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

  const api_map = {
    '/files': {
      'POST': Tasks.Upload.POST,
    },
    '/session': {
      'POST': Tasks.Session.POST,
    },
  };

  export const server = http.createServer((req, res) => {
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
}

export namespace DropServer.Session {
  export type Id = string & { __TYPE__: Id };
  export type Info = {
    id: Id;
    created: number;
    author: string;
    disabled: boolean;
    users: Map<string, string>;
  }

  export const SESSION_OLD_AFTER_DURATION = 24 * 60 * 60 * 1_000;
  export const system: Info;

  const sessions = new Map<Id, Info>();
  const location = path.join(store, 'sessions.json');

  export var init = async () => {
    init = null

    // ensure file system state
    await fs.mkdir(path.join(store, 'sessions_backups')).catch(Fs.ignore_eexist);

    const sessions: Info[] = JSON.parse(await fs.readFile(location, 'utf8'));

    const promises: Promise<any>[] = [];
    const min_date = new Date().valueOf() - SESSION_OLD_AFTER_DURATION;
    for (const session of sessions) {
      const created = new Date(session.created).valueOf();

      session.disabled ||= created > min_date;

      if (session.disabled === false) {
        session.users = new Map() as Info['users'];

        promises.push(
          (async () => {
            for await (const [uid, cred] of read_users(session.id))
              session.users.set(uid, cred);
          })(),
        );
      }

      sessions.set(session.id, session);
    }

    await Promise.all(promises);
  }

  export async function* read_users(session_id: Id) {
    const ents = await fs.readdir(path.join(store, session_id), { withFileTypes: true });

    for (const ent of ents) {
      const parts = ent.name.split(':');
      assert(parts.length == 2);

      yield parts;
    }
  }

  export async function create(id: Id, author: string) {
    await fs.mkdir(path.join(store, id));

    sessions.set(id, {
      id,
      created: new Date().valueOf(),
      author: author,
      disabled: false,
      users: new Map(),
    });
  }

  export function get(id: Id): Info | undefined {
    return sessions.get(id);
  }

  export async function is_disabled(session: Info) {
    if (session.disabled === true)
      return true;

    if (session.created - new Date().valueOf() > SESSION_OLD_AFTER_DURATION)
      return session.disabled = true;

    return false;
  }

  export async function exists(id: Id) {
    return sessions.has(id);
  }

  export async function save() {
    await fs.rename(location, path.join(store, 'sessions_backups', `sessions_${new Date().toISOString()}.json`));
    await fs.writeFile(location, JSON.stringify(sessions.values()), 'utf8');
  }
}

export namespace DropServer.Admin {
  const admin_map = new Map<string, string>();

  export function add(username: string, credentials: string) {
    admin_map.add(username);
  }

  export function delete(username: string) {
    DropServer.Session.system.users.delete(username)l
  }

  export function is(username: string, credentials: string) {
    return DropServer.Session.system.users.get(username) === credentials;
  }
}

export namespace DropServer.Tasks {
  function assertFilePath(ctx: Context): asserts ctx is Context & Context.FilePath {
    const { req, res } = ctx;
    const path = req.headers[DropServer.Constants.Headers.XFilePath];

    if (typeof path !== 'string') // headers may contain non-string values in certain cases, as per nodejs http docs
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

    (ctx as Context & Context.SessionId).session_id = session as DropServer.Session.Id;
  }

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

    (ctx as Context & Context.Auth).auth = { username, password };
  }

  function assertAuthIsAdmin({ res, auth }: Context & Context.Auth) {
    if (Admin.exists(auth.username) !== true)
      throw void res
        .writeHead(403)
        .end();
  }

  export namespace Upload {
    export function POST(ctx: Context) {
      assertAuth(ctx);
      assertSessionId(ctx);
      assertFilePath(ctx);

      const { req, res, auth, session_id, file_path } = ctx;

      const session = DropServer.Session.get(session_id);
      session.

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

      const { req, res, session_id, auth } = ctx;

      // io cannot be asynchronous. this queue prevents race conditoons caused by asynchronous execution
      queue
        .then(async () => {
          if (DropServer.Session.exists(session_id))
            return void res
              .writeHead(400)
              .end('{"message":"Cannot create session with same session id"}');

          await DropServer.Session.create(session_id, auth.username);

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

      const { req, res, auth, session_id } = ctx;

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
