import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto, LoginDto } from './dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs'
import { JwtPayload } from './interfaces/jwt-payload';
import { JwtService } from '@nestjs/jwt';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ){}

  async register(createUserDto: CreateUserDto): Promise<LoginResponse> {
    const user = await this.create(createUserDto);
    return {user: user, token: this.getJwtToken({id: user._id})};
  }

  async login(loginDto: LoginDto): Promise<LoginResponse>{
      const {password, email} = loginDto

      const user = await this.userModel.findOne({email});

      if(!user || !bcryptjs.compareSync(password, user.password) )
        throw new UnauthorizedException('No valid Credentials');

      const {password:_, ...userData} = user.toJSON();

      return {user: userData, token: this.getJwtToken({id: user.id})};
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try{
      const {password, ...userData} = createUserDto;
      
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10), ...userData
      });

      await newUser.save(); 
      
      const {password:_, ...user} = newUser.toObject();

      return user;
     
    } catch(error){
        if(error.code === 11000)
          throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
  }

  async findUserById(id: string) {
    return this.userModel.findById(id);
  }

  async findAll(): Promise<User[]>{
    return await this.userModel.find();
  }

   getJwtToken(payload: JwtPayload){
    return this.jwtService.sign(payload);
  }
}
