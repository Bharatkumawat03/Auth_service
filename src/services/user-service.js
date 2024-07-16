const UserRepository = require('../repository/user-repository');

class UserService {
    constructor() {
        this.UserRepository = new UserRepository();
    }

    async create(data) {
        try {
            const user = await this.UserRepository.create(data);
            return user;
        } catch (error) {
            console.log("Somthing went wrong on service layer");
            throw(error);
        }
    }
}

module.exports = UserService;