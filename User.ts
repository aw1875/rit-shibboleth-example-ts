export default class User {
    FirstName: string;
    LastName: string;
    email: string;

    constructor(FirstName: string, LastName: string, email: string) {
        this.FirstName = FirstName;
        this.LastName = LastName;
        this.email = email;
    }
}
