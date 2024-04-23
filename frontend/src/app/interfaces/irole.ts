export interface IRole {
    id: string;
    name: string;
    home: boolean;
    orderSummary: boolean;
    onlineStore: boolean;
    roles: boolean;
    customers: boolean;
    makeAnOrder: boolean;
    personalData: boolean;
}

export interface createRole {
    name: string;
    home: boolean;
    orderSummary: boolean;
    onlineStore: boolean;
    roles: boolean;
    customers: boolean;
    makeAnOrder: boolean;
    personalData: boolean;
}
