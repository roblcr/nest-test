import { Body, Controller, Get, Post, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { request } from 'http';
import { RequestWithUser } from './jwt.strategy';
import { UserService } from 'src/user/user.service';

export type AuthBody = {email: string; password: string};
export type CreateUser = {email: string; firstName: string; password: string};
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService, private readonly userService: UserService) {}
    @Post('login')
    async login(@Body() authBody: AuthBody) {
        return await this.authService.login({ authBody }); 
    }

    @Post('register')
    async register(@Body() registerBody: CreateUser) {
        return await this.authService.register({ registerBody }); 
    }

    @UseGuards(JwtAuthGuard)
    @Get()
    async authenticateUser(@Request() request: RequestWithUser) {
        console.log(request.user.userId);
        return await this.userService.getUser({userId: request.user.userId});
    }
}
