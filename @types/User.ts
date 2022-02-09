export default class User {
  FirstName: string;
  LastName: string;
  Email: string;
  Student: boolean;

  constructor(
    FirstName: string,
    LastName: string,
    Email: string,
    Student: boolean
  ) {
    this.FirstName = FirstName;
    this.LastName = LastName;
    this.Email = Email;
    this.Student = Student;
  }
}
