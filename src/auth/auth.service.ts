import { Injectable } from '@nestjs/common';
import { AuthBody, CreateUser } from './auth.controller';
import { PrismaService } from 'src/prisma.service';
import { hash, compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserPayload } from './jwt.strategy';

@Injectable()
export class AuthService {
    constructor(private readonly prismaService: PrismaService, private readonly jwtService: JwtService) {}
    async login({ authBody }: { authBody: AuthBody }) {

        const {email, password} = authBody;
        // const hashedPassword = await this.hashPassword(password);

        const existingUser = await this.prismaService.user.findUnique({
            where: { email: authBody.email },
        });

        if (!existingUser) {
            throw new Error('User not found');
        }

        const isPasswordValid = await this.validatePassword(password, existingUser.password);
        if (!isPasswordValid) {
            throw new Error('Invalid password');
        }

        return this.authenticateUser({ userId: existingUser.id });
    }

    async register({ registerBody }: { registerBody: CreateUser }) {

        const {email, firstName, password} = registerBody;

        const existingUser = await this.prismaService.user.findUnique({
            where: {
                email,
            }
        });

        if (existingUser) {
            throw new Error('Un compte existe déjà avec cet email');
        }

        const hashedPassword = await this.hashPassword(password);

        const createdUser = await this.prismaService.user.create({
            data: {
                email,
                firstName,
                password: hashedPassword,
            }
        });

        return this.authenticateUser({ 
            userId: createdUser.id,
        });
    }

    private async hashPassword(password: string) {
        const hashedPassword = await hash(password, 10);
        return hashedPassword;
    }

    private async validatePassword(password: string, hashedPassword: string) {
        const isPasswordValid = await compare(password, hashedPassword);
        return isPasswordValid;
    }

    private async authenticateUser({ userId }: UserPayload) {
        const payload: UserPayload = { userId };
        return {
            access_token: this.jwtService.sign(payload),
        }
    }

}
