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
/**
 * Pagination
 * @export
 * @interface Pagination
 */
export interface Pagination {
    /**
     * Current page
     * @type {number}
     * @memberof Pagination
     */
    index: number;
    /**
     * Amount per page
     * @type {number}
     * @memberof Pagination
     */
    limit: number;
    /**
     * Total page
     * @type {number}
     * @memberof Pagination
     */
    total: number;
}

/**
 * Check if a given object implements the Pagination interface.
 */
export function instanceOfPagination(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "index" in value;
    isInstance = isInstance && "limit" in value;
    isInstance = isInstance && "total" in value;

    return isInstance;
}

export function PaginationFromJSON(json: any): Pagination {
    return PaginationFromJSONTyped(json, false);
}

export function PaginationFromJSONTyped(json: any, ignoreDiscriminator: boolean): Pagination {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'index': json['index'],
        'limit': json['limit'],
        'total': json['total'],
    };
}

export function PaginationToJSON(value?: Pagination | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'index': value.index,
        'limit': value.limit,
        'total': value.total,
    };
}
