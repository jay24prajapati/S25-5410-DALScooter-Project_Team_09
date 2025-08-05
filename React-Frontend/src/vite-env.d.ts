/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE: "https://93u4f3v2x9.execute-api.us-east-1.amazonaws.com/dev";
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
