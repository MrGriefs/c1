export type Session = {
  uuid: Session.Uuid;
  name: string;
  created: Date;
  author: string;
  /** a regular expression to validate against file names */
  file_name_regexp?: string;
} & (
  | { disabled: true }
  | {
    disabled: false;
    // users should never be directly written to
    users: ReadonlyMap<string, string>;
  }
);
export namespace Session {
  export type Uuid = `${string}-${string}-${string}-${string}-${string}` & { __TYPE__: Uuid };

  export type Disabled = Session & {
    disabled: true;
  };

  export type Enabled = Session & {
    disabled: false;
  };
}