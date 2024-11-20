import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginDto } from './dto';
import { AuthGuard } from './guards/guards.guard';
import { LoginResponse } from './interfaces/login-response';
import { User } from './entities/user.entity';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/login')
  login(@Body() loginDto: LoginDto){
    return this.authService.login(loginDto);
  }

  @Post('/register')
  register(@Body() createUserDto: CreateUserDto) {
    return this.authService.register(createUserDto);
  }

  
  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @UseGuards(AuthGuard)
  @Get()
  findAll(@Request() req: Request) {
    return req['user'];
  }

  @UseGuards(AuthGuard)
  @Get('/check-token')
  checkToken(@Request() request: Request): LoginResponse{
    const user = request['user'] as User;

    return {user: user, token: this.authService.getJwtToken({id: user._id})};
  }

}
