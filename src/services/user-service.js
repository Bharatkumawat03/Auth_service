const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const UserRepository = require('../repository/user-repository');
const {JWT_KEY} = require('../config/serverConfig');

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
    
    async signIn(email, plainPassword){
        try {
            //step1 - fetch the user using the email
            const user = await this.UserRepository.getByEmail(email);
            // step2 - compare password
            const passwordMatch = this.checkPassword(plainPassword, user.password);

            if(!passwordMatch){
                console.log("Password dosen't match");
                throw {error: "incorrect password"};
            }
            // step3 - if password match then create a token and send it to the user
            const newJWT = this.createToken({email: user.email, id: user.id});
            return newJWT;
        } catch (error) {
            console.log("Somthing went wrong in the sign in process");
            throw(error);
        }
    }

    async isAuthenticated(token){
        try {
            const response = this.verifyToken(token);
            if(!response){
                throw {error: 'Invalid token'}
            }
            const user = await this.UserRepository.getById(response.id);
            if(!user){
                throw {error: 'No user with the corresponding token exists'};
            }
            return user.id;
        } catch (error) {
            console.log("Somthing went wrong in the auth process");
            throw(error);
        }
    }

    createToken(user){
        try {
            const result = jwt.sign(user, JWT_KEY, {expiresIn: '1d'});
            return result;
        } catch (error) {
            console.log("Somthing went wrong in token creation");
            throw(error);
        }
    }

    verifyToken(token){
        try {
            const result = jwt.verify(token, JWT_KEY);
            return result;
        } catch (error) {
            console.log("Somthing went wrong in token validation", error);
            throw(error);
        }
    }

    checkPassword(userInputPlainPassword, encryptedPassword){
        try {
            return bcrypt.compareSync(userInputPlainPassword, encryptedPassword);
        } catch (error) {
            console.log("Somthing went wrong in password comparison");
            throw(error);
        }
    }
}

module.exports = UserService;