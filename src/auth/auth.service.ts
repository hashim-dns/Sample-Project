import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { promises } from "dns";

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) {

    }
    async signup(dto: AuthDto){
        // Generate the passwordhash
        const hash = await argon.hash(dto.password) 

        // Save the new user in the db
        try
        {
            
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash
                },
            })

            delete user.hash

            // return the saved user
            return this.signToken(user.id, user.email)

        }
        catch(error)
        {
            if(error instanceof PrismaClientKnownRequestError){
                if(error.code == 'P2002'){
                    throw new ForbiddenException('Credentials already taken,You cannot use that')
                }
            }
            throw error;
        }
    }

    async signin(dto: AuthDto){
        // Find the user by Email
        const user = await this.prisma.user.findUnique({
            where:  {
                email: dto.email,
            }
        })
        // If user doesn't exist throw Exception
        if(!user){
            throw new ForbiddenException('Credentials are incorrect')
        }
        // Compare Password
        const passMatches = await argon.verify(user.hash, dto.password)
        // If password is incorrect throw
        if(!passMatches){
            throw new ForbiddenException('Credentials are incorrect')
        }
        // If correct Sign in
        return this.signToken(user.id, user.email)
        // return {msg : "I have Signed In"};
    }

    async signToken(userId: number, email: string):Promise<{access_token: string}>{
        const payload = {
            sub: userId,
            email
        }
        const secret = this.config.get('JWT_SECRET')
        const token = await this.jwt.signAsync(payload,{
            expiresIn: '15m',
            secret: secret
        }) 
        return {
            access_token: token,
        }   
    }
}
