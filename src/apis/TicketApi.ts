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


import * as runtime from '../runtime';
import type {
  CreateTicketRequest,
  Ticket,
} from '../models';
import {
    CreateTicketRequestFromJSON,
    CreateTicketRequestToJSON,
    TicketFromJSON,
    TicketToJSON,
} from '../models';

export interface CreateTicketOperationRequest {
    createTicketRequest?: CreateTicketRequest;
}

/**
 * 
 */
export class TicketApi extends runtime.BaseAPI {

    /**
     */
    async createTicketRaw(requestParameters: CreateTicketOperationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Ticket>> {
        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/tickets`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: CreateTicketRequestToJSON(requestParameters.createTicketRequest),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => TicketFromJSON(jsonValue));
    }

    /**
     */
    async createTicket(requestParameters: CreateTicketOperationRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Ticket> {
        const response = await this.createTicketRaw(requestParameters, initOverrides);
        return await response.value();
    }

}
