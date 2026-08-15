import simple from './index.cjs';

export const Client = simple.Client;
export const defaultConfig = simple.defaultConfig;
export const SimpleError = simple.SimpleError;
export const ErrorKind = simple.ErrorKind;
export const ssoLink = simple.ssoLink;
export const Management = simple.Management;
export const Expiry = simple.Expiry;
export const FetchHttpClient = simple.FetchHttpClient;
export const RESET_GRANTED = simple.RESET_GRANTED;
export const RESET_DENIED = simple.RESET_DENIED;
export const RESET_TOO_SOON = simple.RESET_TOO_SOON;
export default simple;
