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
import type { ServiceType } from './ServiceType';
import {
    ServiceTypeFromJSON,
    ServiceTypeFromJSONTyped,
    ServiceTypeToJSON,
} from './ServiceType';

/**
 * 
 * @export
 * @interface CreateServiceRequest
 */
export interface CreateServiceRequest {
    /**
     * 
     * @type {string}
     * @memberof CreateServiceRequest
     */
    name: string;
    /**
     * 
     * @type {string}
     * @memberof CreateServiceRequest
     */
    title: string;
    /**
     * 
     * @type {string}
     * @memberof CreateServiceRequest
     */
    description: string;
    /**
     * 
     * @type {string}
     * @memberof CreateServiceRequest
     */
    url: string;
    /**
     * 
     * @type {ServiceType}
     * @memberof CreateServiceRequest
     */
    type: ServiceType;
}

/**
 * Check if a given object implements the CreateServiceRequest interface.
 */
export function instanceOfCreateServiceRequest(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "title" in value;
    isInstance = isInstance && "description" in value;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function CreateServiceRequestFromJSON(json: any): CreateServiceRequest {
    return CreateServiceRequestFromJSONTyped(json, false);
}

export function CreateServiceRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): CreateServiceRequest {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'name': json['name'],
        'title': json['title'],
        'description': json['description'],
        'url': json['url'],
        'type': ServiceTypeFromJSON(json['type']),
    };
}

export function CreateServiceRequestToJSON(value?: CreateServiceRequest | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'name': value.name,
        'title': value.title,
        'description': value.description,
        'url': value.url,
        'type': ServiceTypeToJSON(value.type),
    };
}

