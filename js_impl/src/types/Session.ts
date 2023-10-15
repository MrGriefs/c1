export type Session = {
  uuid: Session.Uuid;
  name: string;
  created: Date;
  author: string;
  disabled: boolean;
  users: Map<string, string>;
}
export namespace Session {
  export type Uuid = `${string}-${string}-${string}-${string}-${string}` & { __TYPE__: Uuid };
}