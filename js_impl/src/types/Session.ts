export type Session = {
  uuid: Session.Uuid;
  name: string;
  created: Date;
  author: string;
  disabled: boolean;
  // users should never be directly written to
  users: ReadonlyMap<string, string>;
}
export namespace Session {
  export type Uuid = `${string}-${string}-${string}-${string}-${string}` & { __TYPE__: Uuid };
}