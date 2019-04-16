import { TimePeriod } from './timePeriod';
import * as crypto from "./crypto";

/**
 * A simple interface for a certificate.
 */
export interface Certificate {

    /**
     * The version number, can be used in the future.
     */
    version: number;

    /**
     * The name of the user which holds the public key
     * belonging to this certificate
     */
    subject: string;

    /**
     * The time period in which the certificate is valid.
     */
    validity: TimePeriod;

    /**
     * The signature of the certificate
     */
    signature: crypto.Signature;
}
