import packageMetadata from "../package.json";

/** Build-time application version; synchronized with backend by `npm run version:check`. */
export const APP_VERSION = packageMetadata.version;
