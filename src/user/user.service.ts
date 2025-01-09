import { Injectable } from '@nestjs/common';
import { first } from 'rxjs';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UserService {
    constructor(private readonly prismaService: PrismaService) {}
    async getUsers() {
      const users = await this.prismaService.user.findMany({
        select: {
          id: true,
          email: true, 
          firstName: true,
        },
      });
        return users;
    }

    async getUser({userId}: {userId: string}) {
        const users = await this.prismaService.user.findUnique({
            where: {
                id: userId,
            },
        });
          return users;
      }
}
