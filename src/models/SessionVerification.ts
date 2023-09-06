/* tslint:disable */
/* eslint-disable */
/**
 * BoardWare Cloud APIs
 * BoardWare cloud console api
 *
 * The version of the OpenAPI document: 0.0.12
 * Contact: dan.chen@boardware.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
import type { SessionStatus } from './SessionStatus';
import {
    SessionStatusFromJSON,
    SessionStatusFromJSONTyped,
    SessionStatusToJSON,
} from './SessionStatus';

/**
 * 
 * @export
 * @interface SessionVerification
 */
export interface SessionVerification {
    /**
     * 
     * @type {SessionStatus}
     * @memberof SessionVerification
     */
    status: SessionStatus;
}

/**
 * Check if a given object implements the SessionVerification interface.
 */
export function instanceOfSessionVerification(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "status" in value;

    return isInstance;
}

export function SessionVerificationFromJSON(json: any): SessionVerification {
    return SessionVerificationFromJSONTyped(json, false);
}

export function SessionVerificationFromJSONTyped(json: any, ignoreDiscriminator: boolean): SessionVerification {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'status': SessionStatusFromJSON(json['status']),
    };
}

export function SessionVerificationToJSON(value?: SessionVerification | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'status': SessionStatusToJSON(value.status),
    };
}
