/**
 * This file exposes the public api of the mini-certificate library.
 */
export interface TimePeriod {
    /* Time periods consists of two 32bit integers in unix time*/
    start: number;
    end: number;
}
