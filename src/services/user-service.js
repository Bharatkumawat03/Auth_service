const jwt = require('jsonwebtoken');

const UserRepository = require('../repository/user-repository');
const {JWT_key, JWT_KEY} = require('../config/serverConfig');

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

    createToken(user){
        try {
            const result = jwt.sign(user, JWT_KEY, {expiresIn: '1h'});
            return result;
        } catch (error) {
            console.log("Somthing went wrong on service layer");
            throw(error);
        }
    }
}

module.exports = UserService;